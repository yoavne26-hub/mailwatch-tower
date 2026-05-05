"""Sender identity analyzer placeholder."""

from app.models import AnalyzeRequest, Signal


def analyze_sender(request: AnalyzeRequest) -> list[Signal]:
    """Detect sender identity risk signals.

    TODO: Implement Reply-To mismatch, brand impersonation, typo-squatting,
    and suspicious sender formatting checks.
    """
    _ = request
    return []

