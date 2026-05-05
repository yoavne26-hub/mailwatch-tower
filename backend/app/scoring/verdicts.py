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

