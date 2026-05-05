"""Header and authentication analyzer placeholder."""

from app.models import AnalyzeRequest, Signal


def analyze_headers(request: AnalyzeRequest) -> list[Signal]:
    """Detect email authentication and header consistency risk signals."""
    _ = request
    return []

