"""Verdict mapping for final risk scores."""

from app.scoring.config import VERDICT_COLORS

VERDICT_THRESHOLDS: tuple[tuple[int, int, str], ...] = (
    (0, 19, "Safe"),
    (20, 39, "Low Risk"),
    (40, 59, "Suspicious"),
    (60, 79, "High Risk"),
    (80, 100, "Dangerous"),
)


def verdict_for_score(score: int) -> tuple[str, str]:
    """Return verdict label and color for a final score."""
    bounded_score = max(0, min(100, int(score)))
    for minimum, maximum, verdict in VERDICT_THRESHOLDS:
        if minimum <= bounded_score <= maximum:
            return verdict, VERDICT_COLORS[verdict]
    return "Dangerous", VERDICT_COLORS["Dangerous"]
