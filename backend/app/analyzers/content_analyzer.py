"""Content and social engineering analyzer placeholder."""

from app.models import AnalyzeRequest, Signal


def analyze_content(request: AnalyzeRequest) -> list[Signal]:
    """Detect body text risk signals from bounded, untrusted input."""
    _ = request
    return []

