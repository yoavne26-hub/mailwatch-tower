"""Attachment metadata analyzer placeholder."""

from app.models import AnalyzeRequest, Signal


def analyze_attachments(request: AnalyzeRequest) -> list[Signal]:
    """Detect attachment name and MIME metadata risk signals.

    Attachments must never be opened, downloaded, executed, or scanned.
    """
    _ = request
    return []

