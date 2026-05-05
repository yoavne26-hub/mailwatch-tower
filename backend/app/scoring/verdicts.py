"""Verdict thresholds and colors for overall email risk severity."""

VERDICT_COLORS: dict[str, str] = {
    "Safe": "#188038",
    "Low Risk": "#4FC3F7",
    "Suspicious": "#FBC02D",
    "High Risk": "#F57C00",
    "Dangerous": "#D93025",
}

VERDICT_THRESHOLDS: tuple[tuple[int, int, str], ...] = (
    (0, 14, "Safe"),
    (15, 34, "Low Risk"),
    (35, 59, "Suspicious"),
    (60, 79, "High Risk"),
    (80, 100, "Dangerous"),
)


def verdict_for_score(score: int) -> tuple[str, str]:
    """Return the verdict and color for a capped score."""
    bounded_score = max(0, min(100, score))
    for minimum, maximum, verdict in VERDICT_THRESHOLDS:
        if minimum <= bounded_score <= maximum:
            return verdict, VERDICT_COLORS[verdict]
    return "Dangerous", VERDICT_COLORS["Dangerous"]
