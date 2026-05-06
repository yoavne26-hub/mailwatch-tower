"""Shared analyzer helpers."""

from app.models import CategoryDetail, CategoryStatus, Check, FeedbackAction
from app.scoring.config import CATEGORY_CAPS


def category_score(checks: list[Check], category: str) -> int:
    return min(CATEGORY_CAPS[category], sum(max(0, check.points) for check in checks))


def category_status(checks: list[Check]) -> CategoryStatus:
    if not checks:
        return "passed"
    if any(check.result in {"failed", "match"} and check.points >= 15 for check in checks):
        return "failed"
    if any(check.result in {"failed", "warning", "match"} for check in checks):
        return "warning"
    if all(check.result == "not_available" for check in checks):
        return "not_available"
    return "passed"


def build_category(
    *,
    key: str,
    title: str,
    checks: list[Check],
    feedback_actions: list[FeedbackAction],
    empty_summary: str,
    risk_summary: str,
) -> CategoryDetail:
    score = category_score(checks, key)
    status = category_status(checks)
    return CategoryDetail(
        title=title,
        score=score,
        max_score=CATEGORY_CAPS[key],
        status=status,
        short_summary=risk_summary if score else empty_summary,
        checks=checks,
        feedback_actions=feedback_actions,
    )
