"""Deterministic scoring engine for MailWatch Tower."""

from app.analyzers.attachment_analyzer import analyze_attachments
from app.analyzers.content_analyzer import analyze_content
from app.analyzers.header_analyzer import analyze_headers
from app.analyzers.link_analyzer import analyze_links
from app.analyzers.sender_analyzer import analyze_sender
from app.models import AnalyzeRequest, AnalyzeResponse, Signal
from app.scoring.recommendations import build_recommendations, default_limitations
from app.scoring.verdicts import verdict_for_score
from app.scoring.weights import CATEGORY_COLORS


def score_email(request: AnalyzeRequest) -> AnalyzeResponse:
    """Score an email using deterministic local analyzers."""
    signals = _deduplicate_signals(
        [
            *analyze_sender(request),
            *analyze_links(request),
            *analyze_attachments(request),
            *analyze_content(request),
            *analyze_headers(request),
        ]
    )

    raw_score = sum(signal.points for signal in signals)
    score = min(100, raw_score)
    verdict, verdict_color = verdict_for_score(score)
    category_breakdown = _category_breakdown(signals)

    return AnalyzeResponse(
        score=score,
        raw_score=raw_score,
        verdict=verdict,
        verdict_color=verdict_color,
        summary=_build_summary(verdict, score, signals),
        category_breakdown=category_breakdown,
        signals=signals,
        recommendations=build_recommendations(verdict, signals),
        limitations=default_limitations(),
    )


def _deduplicate_signals(signals: list[Signal]) -> list[Signal]:
    """Keep each exact signal once even if multiple analyzers report it."""
    unique: dict[tuple[str, str], Signal] = {}
    for signal in signals:
        unique.setdefault((signal.category, signal.signal_name), signal)
    return list(unique.values())


def _category_breakdown(signals: list[Signal]) -> dict[str, int]:
    breakdown = {category: 0 for category in CATEGORY_COLORS}
    for signal in signals:
        breakdown[signal.category] = breakdown.get(signal.category, 0) + signal.points
    return breakdown


def _build_summary(verdict: str, score: int, signals: list[Signal]) -> str:
    if not signals:
        return "No strong risk indicators were found in the analyzed email fields."

    top_categories = _top_categories(signals)
    category_text = ", ".join(top_categories)
    return (
        f"{verdict} risk verdict with score {score}. "
        f"Risk indicators found across {category_text}."
    )


def _top_categories(signals: list[Signal]) -> list[str]:
    totals: dict[str, int] = {}
    labels: dict[str, str] = {}
    for signal in signals:
        totals[signal.category] = totals.get(signal.category, 0) + signal.points
        labels[signal.category] = signal.category_label
    sorted_categories = sorted(totals, key=totals.get, reverse=True)
    return [labels[category] for category in sorted_categories[:3]]
