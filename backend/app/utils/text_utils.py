"""Text normalization helper placeholders."""


def compact_whitespace(value: str | None) -> str:
    """Collapse surrounding whitespace for bounded text analysis."""
    if not value:
        return ""
    return " ".join(value.split())

