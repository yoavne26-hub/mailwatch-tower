"""Safe email parsing helper placeholders."""


def normalize_email_address(value: str | None) -> str | None:
    """Normalize an email address string without trusting it as valid."""
    if value is None:
        return None
    return value.strip()

