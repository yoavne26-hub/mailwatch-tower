"""Safe URL parsing helpers."""

import ipaddress
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from app.utils.email_parsing import normalize_domain

URL_PATTERN = re.compile(r"https?://[^\s<>'\")]+", flags=re.IGNORECASE)


def safe_parse_url(value: str):
    """Parse a URL-like string without visiting or fetching it."""
    return urlparse(value)


def extract_urls_from_text(value: str | None) -> list[str]:
    """Extract HTTP(S) URLs from text without fetching them."""
    if not value:
        return []
    return [match.group(0).rstrip(".,;:!?") for match in URL_PATTERN.finditer(value)]


def extract_html_links(html: str | None) -> list[tuple[str, str]]:
    """Return HTML anchor text and href pairs without loading resources."""
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    links: list[tuple[str, str]] = []
    for anchor in soup.find_all("a"):
        href = str(anchor.get("href") or "").strip()
        if href.lower().startswith(("http://", "https://")):
            links.append((anchor.get_text(" ", strip=True), href))
    return links


def hostname_for_url(value: str) -> str | None:
    """Extract a normalized hostname from a URL-like value."""
    try:
        parsed = safe_parse_url(value)
    except ValueError:
        return None
    return normalize_domain(parsed.hostname)


def is_ip_hostname(hostname: str | None) -> bool:
    """Return true if a hostname is an IP address."""
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def tld_for_hostname(hostname: str | None) -> str | None:
    """Return the final domain label for simple TLD checks."""
    if not hostname or "." not in hostname:
        return None
    return hostname.rsplit(".", 1)[-1].lower()


def domain_in_text(value: str) -> str | None:
    """Find a domain-like token in visible link text."""
    match = re.search(
        r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b",
        value.lower(),
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    return normalize_domain(match.group(0))
