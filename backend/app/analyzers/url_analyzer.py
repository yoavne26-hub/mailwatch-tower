"""URL analyzer that never visits links."""

from app.analyzers.common import build_category
from app.config import get_settings
from app.feedback.normalization import normalize_link_domain
from app.models import AnalyzeRequest, CategoryDetail, Check, FeedbackAction, UrlInput
from app.scoring.config import CATEGORY_TITLES, SUSPICIOUS_TLDS, URL_SHORTENERS
from app.utils.email_parsing import parse_email_field
from app.utils.text_utils import normalized_text
from app.utils.url_utils import (
    extract_urls_from_text,
    hostname_for_url,
    is_ip_hostname,
    normalize_url_for_analysis,
    registrable_like_domain,
    tld_for_hostname,
)

KEYWORD_NEAR_URLS = ("login", "sign in", "password", "payment", "pay", "security", "verify", "account", "mfa", "otp")


def analyze_urls(request: AnalyzeRequest) -> CategoryDetail:
    """Analyze extracted URLs using local heuristics only."""
    url_inputs = _combined_url_inputs(request)[: get_settings().max_urls]
    sender_domain = parse_email_field(request.sender_email or request.from_header).domain
    sender_comparison_domain = registrable_like_domain(sender_domain)
    checks: list[Check] = []
    actions: list[FeedbackAction] = []
    seen_check_keys: set[tuple[str, str]] = set()

    if len(url_inputs) > 5:
        checks.append(
            Check(
                name="Excessive number of links",
                result="warning",
                points=7,
                explanation="The message contains more than five links, increasing the chance of confusing or misleading destinations.",
                evidence_summary=f"Detected links: {len(url_inputs)}",
            )
        )

    for url_input in url_inputs:
        normalized_url = normalize_url_for_analysis(url_input.url)
        host = hostname_for_url(normalized_url)
        feedback_domain = normalize_link_domain(host)
        link_domain = registrable_like_domain(host)
        if not normalized_url or not host:
            checks.append(
                Check(
                    name="Malformed URL",
                    result="warning",
                    points=5,
                    explanation="A URL-like value could not be parsed cleanly.",
                    evidence_summary="Malformed URL was handled without visiting it.",
                )
            )
            continue

        if feedback_domain:
            _add_domain_action_pairs(actions, feedback_domain)
        if normalized_url.lower().startswith("http://"):
            _append_unique(
                checks,
                seen_check_keys,
                Check(
                    name="HTTP link",
                    result="warning",
                    points=6,
                    explanation="The message contains a non-HTTPS link, which can expose users to tampering or unsafe redirects.",
                    evidence_summary=f"URL domain: {host}",
                    indicator_type="url",
                    indicator_value=normalized_url,
                ),
            )
        if is_ip_hostname(host):
            _append_unique(
                checks,
                seen_check_keys,
                Check(
                    name="IP-based URL",
                    result="failed",
                    points=15,
                    explanation="The message links directly to an IP address instead of a readable domain.",
                    evidence_summary=f"URL host: {host}",
                    indicator_type="url",
                    indicator_value=normalized_url,
                ),
            )
        if host in URL_SHORTENERS:
            _append_unique(
                checks,
                seen_check_keys,
                Check(
                    name="URL shortener",
                    result="warning",
                    points=10,
                    explanation="The message uses a URL shortener, which hides the final destination from the user.",
                    evidence_summary=f"Shortener domain: {host}",
                    indicator_type="link_domain",
                    indicator_value=feedback_domain or host,
                ),
            )
        if any(part.startswith("xn--") for part in host.split(".")):
            _append_unique(
                checks,
                seen_check_keys,
                Check(
                    name="Punycode domain",
                    result="failed",
                    points=15,
                    explanation="The URL contains a punycode domain, which can be used to disguise lookalike domains.",
                    evidence_summary=f"URL domain: {host}",
                    indicator_type="link_domain",
                    indicator_value=feedback_domain or host,
                ),
            )
        if tld_for_hostname(host) in SUSPICIOUS_TLDS:
            _append_unique(
                checks,
                seen_check_keys,
                Check(
                    name="Suspicious top-level domain",
                    result="warning",
                    points=8,
                    explanation="The URL uses a top-level domain commonly seen in risky campaigns.",
                    evidence_summary=f"URL domain: {host}",
                    indicator_type="link_domain",
                    indicator_value=feedback_domain or host,
                ),
            )
        if sender_comparison_domain and link_domain and link_domain != sender_comparison_domain:
            _append_unique(
                checks,
                seen_check_keys,
                Check(
                    name="Link domain differs from sender domain",
                    result="warning",
                    points=8,
                    explanation="A link points to a domain different from the sender domain, which may indicate a redirected or third-party destination.",
                    evidence_summary=f"Sender domain: {sender_comparison_domain}; link domain: {link_domain}",
                    indicator_type="link_domain",
                    indicator_value=feedback_domain or host,
                ),
            )
        if _keyword_near_url(url_input, request):
            _append_unique(
                checks,
                seen_check_keys,
                Check(
                    name="Login/payment/security keyword near URL",
                    result="warning",
                    points=10,
                    explanation="A link appears near login, payment, or security language, which may indicate credential or financial targeting.",
                    evidence_summary=f"URL domain: {host}",
                    indicator_type="url",
                    indicator_value=normalized_url,
                ),
            )

    return build_category(
        key="links",
        title=CATEGORY_TITLES["links"],
        checks=checks,
        feedback_actions=_dedupe_actions(actions),
        empty_summary="No URL risk indicators were detected in the analyzed fields.",
        risk_summary="URL indicators require review.",
    )


def _combined_url_inputs(request: AnalyzeRequest) -> list[UrlInput]:
    url_inputs = list(request.urls)
    existing = {item.url for item in url_inputs}
    for url in extract_urls_from_text(request.body_text):
        if url not in existing:
            url_inputs.append(UrlInput(url=url, source="body_text"))
            existing.add(url)
    return url_inputs


def _keyword_near_url(url_input: UrlInput, request: AnalyzeRequest) -> bool:
    context = normalized_text(url_input.anchor_text, url_input.surrounding_text, request.subject)
    if not context:
        context = normalized_text(request.body_text)
    return any(keyword in context for keyword in KEYWORD_NEAR_URLS)


def _append_unique(checks: list[Check], seen: set[tuple[str, str]], check: Check) -> None:
    key = (check.name, check.indicator_value or check.evidence_summary)
    if key not in seen:
        checks.append(check)
        seen.add(key)


def _add_domain_action_pairs(actions: list[FeedbackAction], domain: str) -> None:
    actions.extend(
        [
            FeedbackAction(label=f"Trust domain: {domain}", action="mark_trusted", indicator_type="link_domain", indicator_value=domain, source_category="links"),
            FeedbackAction(label=f"Mark domain malicious: {domain}", action="mark_malicious", indicator_type="link_domain", indicator_value=domain, source_category="links"),
        ]
    )


def _dedupe_actions(actions: list[FeedbackAction]) -> list[FeedbackAction]:
    unique: dict[tuple[str, str, str], FeedbackAction] = {}
    for action in actions:
        unique.setdefault((action.action, action.indicator_type, action.indicator_value.lower()), action)
    return list(unique.values())[:12]
