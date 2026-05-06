"""Optional Google Safe Browsing enrichment."""

from dataclasses import dataclass
from typing import Protocol

import httpx

from app.analyzers.common import build_category
from app.config import get_settings
from app.models import AnalyzeRequest, CategoryDetail, Check
from app.scoring.config import CATEGORY_TITLES, SAFE_BROWSING_MATCH_POINTS
from app.utils.url_utils import hostname_for_url, normalize_url_for_analysis
from app.utils.url_utils import extract_urls_from_text

SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SAFE_BROWSING_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


class SafeBrowsingClientProtocol(Protocol):
    def check_urls(self, urls: list[str]) -> dict[str, list[str]]:
        """Return URL -> threat labels for matched URLs."""


@dataclass
class SafeBrowsingClient:
    """Google Safe Browsing v4 Lookup API client, isolated for tests."""

    api_key: str
    timeout_seconds: float = 5.0

    def check_urls(self, urls: list[str]) -> dict[str, list[str]]:
        if not urls:
            return {}
        api_url = f"{SAFE_BROWSING_ENDPOINT}?key={self.api_key}"
        body = {
            "client": {"clientId": "mailwatch-tower", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": SAFE_BROWSING_THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url} for url in urls],
            },
        }
        response = httpx.post(api_url, json=body, timeout=self.timeout_seconds)
        response.raise_for_status()
        payload = response.json()
        matches: dict[str, list[str]] = {}
        for match in payload.get("matches", []):
            url = match.get("threat", {}).get("url")
            if url:
                matches.setdefault(normalize_url_for_analysis(url), []).append(_threat_label(match))
        return matches


GoogleSafeBrowsingClient = SafeBrowsingClient


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
                name="Google Safe Browsing",
                result="not_available",
                points=0,
                explanation="No URLs were available for external threat-intelligence checks.",
                evidence_summary="No external URL reputation lookup was performed.",
            )
        )
    elif not settings.safe_browsing_api_key and client is None:
        checks.append(
            Check(
                name="Google Safe Browsing",
                result="not_available",
                points=0,
                explanation="Safe Browsing enrichment is disabled because SAFE_BROWSING_API_KEY is not configured.",
                evidence_summary="No external URL reputation lookup was performed.",
            )
        )
    else:
        safe_client = client or SafeBrowsingClient(
            api_key=settings.safe_browsing_api_key or "",
            timeout_seconds=settings.safe_browsing_timeout_seconds,
        )
        try:
            matches = safe_client.check_urls(urls)
        except Exception:
            checks.append(
                Check(
                    name="Google Safe Browsing",
                    result="not_available",
                    points=0,
                    explanation="Safe Browsing enrichment could not be completed.",
                    evidence_summary="Local heuristics were still applied.",
                )
            )
        else:
            if matches:
                for url, threats in matches.items():
                    host = hostname_for_url(url) or "unknown"
                    checks.append(
                        Check(
                            name="Google Safe Browsing match",
                            result="match",
                            points=SAFE_BROWSING_MATCH_POINTS,
                            explanation="External threat intelligence reported one or more URLs as unsafe.",
                            evidence_summary=f"Matched domain: {host}; threat details: {', '.join(threats)}",
                            indicator_type="url",
                            indicator_value=url,
                            is_critical=True,
                        )
                    )
            else:
                checks.append(
                    Check(
                        name="Google Safe Browsing",
                        result="no_match",
                        points=0,
                        explanation="No known Safe Browsing match was found for the extracted URLs.",
                        evidence_summary=f"Checked {len(urls)} extracted URL(s).",
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
    return list(dict.fromkeys(url for url in urls if url))[: get_settings().safe_browsing_max_urls]


def _threat_label(match: dict[str, object]) -> str:
    threat_type = str(match.get("threatType") or "UNKNOWN")
    platform_type = str(match.get("platformType") or "UNKNOWN_PLATFORM")
    return f"{threat_type}/{platform_type}"
