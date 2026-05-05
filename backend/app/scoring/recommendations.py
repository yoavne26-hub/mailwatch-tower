"""Recommendation placeholders for analyzed emails."""


def default_limitations() -> list[str]:
    """Return baseline limitations for deterministic local analysis."""
    return [
        "MailWatch Tower does not open attachments or visit links.",
        "The score is based on risk indicators, not definitive malware confirmation.",
    ]

