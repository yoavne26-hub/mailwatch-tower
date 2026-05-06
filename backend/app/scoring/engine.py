"""Documented scoring engine for MailWatch Tower."""

from uuid import uuid4

from app.analyzers.attachment_analyzer import analyze_attachments
from app.analyzers.content_analyzer import analyze_content
from app.analyzers.enrichment_analyzer import SafeBrowsingClientProtocol, analyze_external_intel
from app.analyzers.sender_auth_analyzer import analyze_sender_auth
from app.analyzers.url_analyzer import analyze_urls
from app.feedback.repository import FeedbackIndicator
from app.feedback.service import FeedbackService
from app.models import AnalyzeRequest, AnalyzeResponse, AppliedAdjustment, CategoryDetail, Check
from app.scoring.config import CATEGORY_TITLES, VERDICT_COLORS
from app.scoring.feedback_adjustments import apply_feedback_adjustments
from app.scoring.verdicts import verdict_for_score


def analyze_email(
    request: AnalyzeRequest,
    *,
    feedback_service: FeedbackService | None = None,
    safe_browsing_client: SafeBrowsingClientProtocol | None = None,
) -> AnalyzeResponse:
    """Analyze an email and return a UI-ready response."""
    categories = {
        "sender_auth": analyze_sender_auth(request),
        "links": analyze_urls(request),
        "attachments": analyze_attachments(request),
        "content": analyze_content(request),
        "external_intel": analyze_external_intel(request, client=safe_browsing_client),
    }
    base_category_scores = {key: category.score for key, category in categories.items()}
    base_score = sum(base_category_scores.values())

    feedback = (feedback_service or FeedbackService()).matching_feedback(request)
    adjusted_categories, adjustments = apply_feedback_adjustments(request, categories, feedback)
    category_scores = {key: category.score for key, category in adjusted_categories.items()}
    final_score = max(0, min(100, sum(category_scores.values())))
    verdict, verdict_color = verdict_for_score(final_score)
    recommended_actions = _recommended_actions(verdict, adjusted_categories)

    return AnalyzeResponse(
        analysis_id=f"analysis_{uuid4().hex}",
        message_fingerprint=request.message_fingerprint or "",
        final_score=final_score,
        base_score=base_score,
        verdict=verdict,
        summary=_summary(verdict, adjusted_categories),
        category_scores=category_scores,
        applied_adjustments=adjustments,
        categories=adjusted_categories,
        recommended_actions=recommended_actions,
        score=final_score,
        raw_score=base_score,
        verdict_color=verdict_color,
        category_breakdown=category_scores,
        signals=_compatibility_signals(adjusted_categories),
        recommendations=recommended_actions,
        limitations=[
            "MailWatch Tower does not open attachments or visit links.",
            "The score is based on detected risk indicators, not definitive malware confirmation.",
            "Legitimate messages can still contain suspicious-looking patterns.",
        ],
    )


def score_email(request: AnalyzeRequest) -> AnalyzeResponse:
    """Backward-compatible name for older callers."""
    return analyze_email(request)


def _summary(verdict: str, categories: dict[str, CategoryDetail]) -> str:
    risky_categories = [
        category.title
        for key, category in categories.items()
        if key != "user_feedback" and category.score > 0
    ]
    if verdict == "Safe":
        return "No major malicious-email indicators were detected in the analyzed fields."
    if not risky_categories:
        return f"This message was marked as {verdict} based on detected risk indicators."
    if verdict == "Dangerous":
        return (
            "This message was marked as Dangerous because multiple high-risk indicators "
            f"were found across {_readable_list(risky_categories)}."
        )
    return (
        f"This message was marked as {verdict} because risk indicators were found "
        f"across {_readable_list(risky_categories)}."
    )


def _recommended_actions(verdict: str, categories: dict[str, CategoryDetail]) -> list[str]:
    has_attachments = categories.get("attachments", CategoryDetail(title="", score=0, max_score=0, status="passed", short_summary="")).score > 0
    has_links = categories.get("links", CategoryDetail(title="", score=0, max_score=0, status="passed", short_summary="")).score > 0
    if verdict in {"Dangerous", "High Risk"}:
        actions = [
            "Do not click links or open attachments.",
            "Verify the request through a separate trusted channel.",
            "Report the message using your organization's phishing reporting process.",
        ]
    elif verdict == "Suspicious":
        actions = [
            "Review the highlighted indicators before taking action.",
            "Verify the sender through a trusted channel.",
        ]
        if has_links:
            actions.append("Avoid clicking links unless the request is expected.")
    else:
        actions = [
            "No immediate action is required based on detected indicators.",
            "Continue to verify unexpected requests through normal channels.",
        ]
    if has_attachments and "Do not click links or open attachments." not in actions:
        actions.append("Do not open attachments unless the sender and request are verified.")
    return actions


def _compatibility_signals(categories: dict[str, CategoryDetail]) -> list[dict[str, object]]:
    signals: list[dict[str, object]] = []
    for key, category in categories.items():
        for check in category.checks:
            if check.points <= 0:
                continue
            signals.append(
                {
                    "category": key,
                    "category_label": category.title,
                    "category_color": _category_color(key),
                    "name": check.name,
                    "severity": _severity_for_check(check),
                    "points": check.points,
                    "explanation": check.explanation,
                }
            )
    return signals


def _category_color(category: str) -> str:
    return {
        "sender_auth": "#A67C52",
        "links": "#0B3D91",
        "attachments": "#E91E63",
        "content": "#000000",
        "external_intel": "#6A1B9A",
        "user_feedback": "#4A4A4A",
    }.get(category, "#4A4A4A")


def _severity_for_check(check: Check) -> str:
    if check.points >= 20 or check.is_critical:
        return "high"
    if check.points >= 10:
        return "medium"
    return "low"


def _readable_list(values: list[str]) -> str:
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return ", ".join(values[:-1]) + f", and {values[-1]}"
