"""Links and URLs analyzer."""

from app.config import get_settings
from app.models import AnalyzeRequest, Signal
from app.scoring.weights import make_signal
from app.utils.text_utils import normalized_text, strip_html
from app.utils.url_utils import (
    domain_in_text,
    extract_html_links,
    extract_urls_from_text,
    hostname_for_url,
    is_ip_hostname,
    tld_for_hostname,
)

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "support"}
KEYWORD_NEAR_URLS = ("login", "sign in", "password", "payment", "pay", "security", "verify", "account")


def analyze_links(request: AnalyzeRequest) -> list[Signal]:
    """Detect URL risk signals without visiting or fetching links."""
    settings = get_settings()
    raw_urls = extract_urls_from_text(request.plain_body) + extract_urls_from_text(request.html_body)
    html_links = extract_html_links(request.html_body)
    raw_urls.extend(href for _, href in html_links)

    urls = list(dict.fromkeys(raw_urls))[: settings.max_urls]
    found_signal_ids: set[str] = set()

    if len(urls) > 5:
        found_signal_ids.add("links.more_than_5")

    for url in urls:
        lowered_url = url.lower()
        hostname = hostname_for_url(url)
        if lowered_url.startswith("http://"):
            found_signal_ids.add("links.http_link")
        if is_ip_hostname(hostname):
            found_signal_ids.add("links.ip_url")
        if hostname in SHORTENER_DOMAINS:
            found_signal_ids.add("links.shortened_url")
        if hostname and any(label.startswith("xn--") for label in hostname.split(".")):
            found_signal_ids.add("links.punycode_domain")
        if tld_for_hostname(hostname) in SUSPICIOUS_TLDS:
            found_signal_ids.add("links.suspicious_tld")

    for anchor_text, href in html_links[: settings.max_urls]:
        displayed_domain = domain_in_text(anchor_text)
        actual_domain = hostname_for_url(href)
        if displayed_domain and actual_domain and displayed_domain != actual_domain:
            found_signal_ids.add("links.anchor_mismatch")

    if urls and _keyword_near_any_url(request):
        found_signal_ids.add("links.keyword_near_url")

    return [make_signal(signal_id) for signal_id in sorted(found_signal_ids)]


def _keyword_near_any_url(request: AnalyzeRequest) -> bool:
    text = normalized_text(request.subject, request.plain_body, strip_html(request.html_body))
    for url in extract_urls_from_text(text):
        index = text.find(url.lower())
        if index == -1:
            continue
        window = text[max(0, index - 80) : index + len(url) + 80]
        if any(keyword in window for keyword in KEYWORD_NEAR_URLS):
            return True

    if extract_html_links(request.html_body):
        html_text = normalized_text(strip_html(request.html_body))
        return any(keyword in html_text for keyword in KEYWORD_NEAR_URLS)
    return False
