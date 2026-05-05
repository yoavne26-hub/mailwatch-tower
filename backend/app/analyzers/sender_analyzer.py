"""Sender identity analyzer."""

from app.models import AnalyzeRequest, Signal
from app.scoring.weights import make_signal
from app.utils.email_parsing import ParsedEmail, parse_email_field
from app.utils.text_utils import normalized_text
from app.utils.url_utils import extract_urls_from_text, hostname_for_url

FREE_PROVIDERS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "protonmail.com"}
KNOWN_BRANDS = {"google", "microsoft", "paypal", "amazon", "apple", "github", "upwind", "linkedin", "docusign", "dropbox"}
ORG_WORDS = {
    "security",
    "support",
    "billing",
    "finance",
    "payroll",
    "admin",
    "helpdesk",
    "office",
    "team",
    "hr",
}


def analyze_sender(request: AnalyzeRequest) -> list[Signal]:
    """Detect sender identity risk signals."""
    from_field = parse_email_field(request.from_)
    reply_to = parse_email_field(request.reply_to)
    raw_from = request.from_ or ""
    text_identity = normalized_text(from_field.display_name, from_field.address)
    body_text = normalized_text(request.plain_body, request.html_body)

    found_signal_ids: set[str] = set()

    if from_field.domain and reply_to.domain and from_field.domain != reply_to.domain:
        found_signal_ids.add("sender.reply_to_mismatch")
    if from_field.domain in FREE_PROVIDERS and _looks_organizational(text_identity):
        found_signal_ids.add("sender.free_provider_org")
    if _display_name_uses_external_brand(text_identity, from_field.domain):
        found_signal_ids.add("sender.brand_impersonation")
    if _domain_looks_typosquatted(from_field.domain):
        found_signal_ids.add("sender.typosquat_domain")
    if _body_mentions_other_domain(body_text, from_field.domain):
        found_signal_ids.add("sender.body_domain_mismatch")
    if _has_suspicious_formatting(raw_from, from_field):
        found_signal_ids.add("sender.suspicious_formatting")

    return [make_signal(signal_id) for signal_id in sorted(found_signal_ids)]


def _looks_organizational(text: str) -> bool:
    return any(word in text for word in ORG_WORDS) or any(brand in text for brand in KNOWN_BRANDS)


def _display_name_uses_external_brand(text: str, domain: str | None) -> bool:
    if not domain:
        return False
    for brand in KNOWN_BRANDS:
        if brand in text and brand not in domain:
            return True
    return False


def _domain_looks_typosquatted(domain: str | None) -> bool:
    if not domain:
        return False
    registrable_label = domain.split(".")[0]
    normalized_label = _replace_lookalikes(registrable_label)
    for brand in KNOWN_BRANDS:
        if registrable_label == brand:
            continue
        if normalized_label == brand:
            return True
        if _edit_distance_one_or_less(registrable_label, brand):
            return True
    return False


def _replace_lookalikes(value: str) -> str:
    return value.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a"}))


def _edit_distance_one_or_less(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1:
        return False
    if left == right:
        return True
    if len(left) == len(right):
        return sum(1 for a, b in zip(left, right) if a != b) <= 1
    shorter, longer = sorted((left, right), key=len)
    for index in range(len(longer)):
        if shorter == longer[:index] + longer[index + 1 :]:
            return True
    return False


def _body_mentions_other_domain(text: str, from_domain: str | None) -> bool:
    if not text or not from_domain:
        return False
    domains: set[str] = set()
    for url in extract_urls_from_text(text):
        hostname = hostname_for_url(url)
        if hostname:
            domains.add(hostname)
    for brand in KNOWN_BRANDS:
        if f"{brand}.com" in text:
            domains.add(f"{brand}.com")
    return any(domain != from_domain and not domain.endswith("." + from_domain) for domain in domains)


def _has_suspicious_formatting(raw_from: str, parsed: ParsedEmail) -> bool:
    if not raw_from.strip():
        return False
    if raw_from.count("@") > 1:
        return True
    if "@" not in parsed.address:
        return True
    return any(token in raw_from for token in ("=?utf-8?", "\n", "\r"))
