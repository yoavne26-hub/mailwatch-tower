"""Safe URL parsing helper placeholders."""

from urllib.parse import urlparse


def safe_parse_url(value: str):
    """Parse a URL-like string without visiting or fetching it."""
    return urlparse(value)

