"""Feedback indicator normalization and hashing."""

from hashlib import sha256
from urllib.parse import urlsplit, urlunsplit

from app.models import IndicatorType
from app.utils.email_parsing import normalize_domain, parse_email_field
from app.utils.url_utils import hostname_for_url


def normalize_indicator(indicator_type: IndicatorType, value: str) -> str:
    """Normalize feedback indicators before storing or matching."""
    raw_value = (value or "").strip()
    if indicator_type == "sender_email":
        parsed = parse_email_field(raw_value)
        return (parsed.address or raw_value).lower()
    if indicator_type in {"sender_domain", "reply_to_domain", "link_domain"}:
        return normalize_domain(raw_value) or raw_value.lower()
    if indicator_type == "url":
        return normalize_url_for_feedback(raw_value)
    if indicator_type in {"attachment_extension", "attachment_filename_pattern"}:
        return raw_value.lower().lstrip(".")
    return raw_value.lower()


def normalize_url_for_feedback(value: str) -> str:
    """Normalize URL feedback without preserving sensitive query fragments."""
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return value.strip().lower()
    scheme = (parsed.scheme or "https").lower()
    netloc = (parsed.netloc or "").lower()
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def indicator_hash(normalized_value: str) -> str:
    """Hash normalized indicator values for matching and privacy."""
    return sha256(normalized_value.encode("utf-8", errors="ignore")).hexdigest()


def domain_for_url_indicator(value: str) -> str | None:
    """Return normalized domain for a URL indicator."""
    return hostname_for_url(value)
