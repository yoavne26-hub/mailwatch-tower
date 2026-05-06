"""Optional external intelligence enrichment."""

from dataclasses import dataclass
from typing import Protocol

import httpx

from app.analyzers.common import build_category
from app.config import get_settings
from app.models import AnalyzeRequest, CategoryDetail, Check
from app.scoring.config import CATEGORY_TITLES
from app.utils.url_utils import hostname_for_url, normalize_url_for_analysis
from app.utils.url_utils import extract_urls_from_text


class SafeBrowsingClientProtocol(Protocol):
    def check_urls(self, urls: list[str]) -> dict[str, list[str]]:
        """Return URL -> threat labels for matched URLs."""


@dataclass
class GoogleSafeBrowsingClient:
    """Minimal Google Safe Browsing client, isolated for tests."""

    api_key: str

    def check_urls(self, urls: list[str]) -> dict[str, list[str]]:
        if not urls:
            return {}
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        body = {
            "client": {"clientId": "mailwatch-tower", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url} for url in urls],
            },
        }
        response = httpx.post(api_url, json=body, timeout=5)
        response.raise_for_status()
        payload = response.json()
        matches: dict[str, list[str]] = {}
        for match in payload.get("matches", []):
            url = match.get("threat", {}).get("url")
            if url:
                matches.setdefault(normalize_url_for_analysis(url), []).append(match.get("threatType", "UNKNOWN"))
        return matches


def analyze_external_intel(
    request: AnalyzeRequest,
    client: SafeBrowsingClientProtocol | None = None,
) -> CategoryDetail:
    """Run optional Safe Browsing enrichment for extracted URLs."""
    urls = _request_urls(request)
    settings = get_settings()
    checks: list[Check] = []

    if not urls:
        checks.append(
            Check(
                name="Safe Browsing URL check",
                result="not_available",
                points=0,
                explanation="No URLs were available for external threat intelligence checks.",
                evidence_summary="No URLs extracted.",
            )
        )
    elif not settings.safe_browsing_api_key and client is None:
        checks.append(
            Check(
                name="Safe Browsing URL check",
                result="not_available",
                points=0,
                explanation="Safe Browsing enrichment is not configured. Local heuristics still ran.",
                evidence_summary="SAFE_BROWSING_API_KEY is not set.",
            )
        )
    else:
        safe_client = client or GoogleSafeBrowsingClient(settings.safe_browsing_api_key or "")
        try:
            matches = safe_client.check_urls(urls)
        except Exception:
            checks.append(
                Check(
                    name="Safe Browsing URL check",
                    result="not_available",
                    points=0,
                    explanation="Safe Browsing enrichment was unavailable. Local heuristics still ran.",
                    evidence_summary="External enrichment request failed gracefully.",
                )
            )
        else:
            if matches:
                for url, threats in matches.items():
                    host = hostname_for_url(url) or "unknown"
                    checks.append(
                        Check(
                            name="Safe Browsing match",
                            result="match",
                            points=50,
                            explanation="External threat intelligence reported a match for this URL.",
                            evidence_summary=f"Matched URL domain: {host}; threat types: {', '.join(threats)}",
                            indicator_type="url",
                            indicator_value=url,
                            is_critical=True,
                        )
                    )
            else:
                checks.append(
                    Check(
                        name="Safe Browsing URL check",
                        result="no_match",
                        points=0,
                        explanation="No known Safe Browsing match found for extracted URLs.",
                        evidence_summary=f"Checked URL count: {len(urls)}",
                    )
                )

    return build_category(
        key="external_intel",
        title=CATEGORY_TITLES["external_intel"],
        checks=checks,
        feedback_actions=[],
        empty_summary="External intelligence did not add risk points.",
        risk_summary="External threat intelligence reported a match.",
    )


def _request_urls(request: AnalyzeRequest) -> list[str]:
    urls = [normalize_url_for_analysis(item.url) for item in request.urls if item.url]
    urls.extend(normalize_url_for_analysis(url) for url in extract_urls_from_text(request.body_text))
    return list(dict.fromkeys(urls))[: get_settings().max_urls]
