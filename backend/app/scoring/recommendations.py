"""Recommendation helpers for analyzed emails."""

from app.models import Signal


def default_limitations() -> list[str]:
    """Return baseline limitations for deterministic local analysis."""
    return [
        "MailWatch Tower does not open attachments or visit links.",
        "The score is based on risk indicators, not definitive malware confirmation.",
    ]


def build_recommendations(verdict: str, signals: list[Signal]) -> list[str]:
    """Create user-facing recommendations from verdict and signal categories."""
    categories = {signal.category for signal in signals}
    names = {signal.signal_name for signal in signals}

    if verdict == "Safe":
        return [
            "No strong risk indicators were found.",
            "Continue to use normal caution with links and attachments.",
        ]

    recommendations: list[str] = []
    if verdict in {"High Risk", "Dangerous"}:
        recommendations.append("Do not click links or open attachments.")
    else:
        recommendations.append("Review the highlighted risk indicators before taking action.")

    if {"sender", "headers"} & categories:
        recommendations.append("Verify the sender through a trusted channel.")
    if {"Credential request", "MFA/security reset lure"} & names:
        recommendations.append("Do not enter credentials from links in this message.")
    if {"Payment or wire transfer request", "Fake invoice/order/payment lure"} & names:
        recommendations.append("Confirm financial requests using an approved process.")
    if "attachments" in categories:
        recommendations.append("Do not open attachments unless the sender and request are verified.")
    if verdict in {"Suspicious", "High Risk", "Dangerous"}:
        recommendations.append("Report the message if it was unexpected.")

    return list(dict.fromkeys(recommendations))
