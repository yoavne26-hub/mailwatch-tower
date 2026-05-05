"""Placeholder scoring engine.

TODO: Sum unique detected signal weights, cap the final score at 100, keep the
uncapped raw_score, and return category_breakdown for explainability.
"""

from app.models import AnalyzeRequest, AnalyzeResponse


def score_email(request: AnalyzeRequest) -> AnalyzeResponse:
    """Score an email request.

    This is intentionally unimplemented in the scaffold.
    """
    raise NotImplementedError("Scoring engine will be implemented in a later step.")

