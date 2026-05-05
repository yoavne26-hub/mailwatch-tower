"""Text normalization helpers."""

import re

from bs4 import BeautifulSoup


def compact_whitespace(value: str | None) -> str:
    """Collapse surrounding whitespace for bounded text analysis."""
    if not value:
        return ""
    return " ".join(value.split())


def strip_html(value: str | None) -> str:
    """Convert HTML to plain text without fetching external resources."""
    if not value:
        return ""
    return BeautifulSoup(value, "html.parser").get_text(" ")


def normalized_text(*values: str | None) -> str:
    """Join values into lowercase, compact text for deterministic matching."""
    return compact_whitespace(" ".join(value or "" for value in values)).lower()


def contains_any_pattern(text: str, patterns: tuple[str, ...]) -> bool:
    """Return true when text contains any regex pattern."""
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)
