"""Links and URLs analyzer placeholder."""

from app.models import AnalyzeRequest, Signal


def analyze_links(request: AnalyzeRequest) -> list[Signal]:
    """Detect URL risk signals without visiting or fetching links."""
    _ = request
    return []

