"""Feedback adjustment logic for trusted and malicious indicators."""

from copy import deepcopy

from app.analyzers.common import category_status
from app.feedback.normalization import domain_for_url_indicator, normalize_indicator
from app.feedback.repository import FeedbackIndicator
from app.models import AnalyzeRequest, AppliedAdjustment, CategoryDetail, Check
from app.scoring.config import (
    CATEGORY_TITLES,
    MALICIOUS_FEEDBACK_CAP,
    MALICIOUS_FEEDBACK_POINTS,
    TRUSTED_SENDER_REMAINING_HEURISTIC_REDUCTION,
)

MAJOR_AUTH_FAILURES = {"SPF fail", "DKIM fail", "DMARC fail"}


def apply_feedback_adjustments(
    request: AnalyzeRequest,
    categories: dict[str, CategoryDetail],
    feedback_matches: list[FeedbackIndicator],
) -> tuple[dict[str, CategoryDetail], list[AppliedAdjustment]]:
    """Apply trusted and malicious user feedback without suppressing critical signals."""
    adjusted = {key: value.model_copy(deep=True) for key, value in categories.items()}
    adjustments: list[AppliedAdjustment] = []
    trusted_matches = [match for match in feedback_matches if match.label == "trusted"]
    malicious_matches = [match for match in feedback_matches if match.label == "malicious"]

    _apply_trusted_sender(request, adjusted, trusted_matches, adjustments)
    _apply_trusted_urls(adjusted, trusted_matches, adjustments)
    _apply_malicious_matches(adjusted, malicious_matches, adjustments)
    _apply_safe_browsing_trust_conflicts(adjusted, trusted_matches, adjustments)

    for category in adjusted.values():
        if category.title != CATEGORY_TITLES["user_feedback"]:
            category.score = _capped_score(category)
            category.status = category_status(category.checks)
            if category.score == 0:
                category.short_summary = _zero_score_summary(category)
    return adjusted, adjustments


def _apply_trusted_sender(
    request: AnalyzeRequest,
    categories: dict[str, CategoryDetail],
    trusted_matches: list[FeedbackIndicator],
    adjustments: list[AppliedAdjustment],
) -> None:
    sender_email = (request.sender_email or "").lower()
    exact_sender_trusted = any(
        match.indicator_type == "sender_email"
        and normalize_indicator("sender_email", sender_email) == match.indicator_value
        for match in trusted_matches
    )
    if not exact_sender_trusted or "sender_auth" not in categories:
        return

    sender_auth = categories["sender_auth"]
    removed_points = 0
    for check in sender_auth.checks:
        if check.name in MAJOR_AUTH_FAILURES or check.is_critical:
            continue
        if check.points > 0:
            removed_points += check.points
            check.points = 0
            check.result = "warning"
            check.explanation += " This sender was trusted by the user, so sender identity heuristic points were removed."

    if removed_points:
        adjustments.append(
            AppliedAdjustment(
                type="trusted_sender_identity_zeroed",
                points=-removed_points,
                explanation="Exact sender was trusted by the user, so sender identity heuristic points were removed. Critical signals were not suppressed.",
                indicator_type="sender_email",
                indicator_value=sender_email,
            )
        )

    eligible_remaining_score = _remaining_heuristic_score(categories)
    reduction = int(eligible_remaining_score * TRUSTED_SENDER_REMAINING_HEURISTIC_REDUCTION)
    if reduction > 0:
        _ensure_user_feedback_category(categories).score -= reduction
        adjustments.append(
            AppliedAdjustment(
                type="trusted_sender_remaining_heuristic_reduction",
                points=-reduction,
                explanation="Exact sender was trusted by the user, so remaining non-critical heuristic score was reduced by 20%.",
                indicator_type="sender_email",
                indicator_value=sender_email,
            )
        )


def _apply_trusted_urls(
    categories: dict[str, CategoryDetail],
    trusted_matches: list[FeedbackIndicator],
    adjustments: list[AppliedAdjustment],
) -> None:
    if "links" not in categories:
        return
    trusted_values = {(match.indicator_type, match.indicator_value) for match in trusted_matches}
    trusted_domains = {
        match.indicator_value
        for match in trusted_matches
        if match.indicator_type == "link_domain"
    }
    removed = 0
    for check in categories["links"].checks:
        if check.points <= 0 or check.indicator_type not in {"url", "link_domain"} or not check.indicator_value:
            continue
        normalized_value = normalize_indicator(check.indicator_type, check.indicator_value)
        check_domain = _domain_for_link_check(check)
        if (check.indicator_type, normalized_value) in trusted_values or (
            check_domain is not None and check_domain in trusted_domains
        ):
            removed += check.points
            check.points = 0
            check.result = "warning"
            check.explanation += " This indicator was trusted by the user, so local URL heuristic points were removed."

    if removed:
        adjustments.append(
            AppliedAdjustment(
                type="trusted_url_or_domain_reduction",
                points=-removed,
                explanation="Trusted URL/domain feedback removed matching local URL heuristic points. External intelligence was not suppressed.",
            )
        )


def _apply_malicious_matches(
    categories: dict[str, CategoryDetail],
    malicious_matches: list[FeedbackIndicator],
    adjustments: list[AppliedAdjustment],
) -> None:
    if not malicious_matches:
        return
    user_feedback = _ensure_user_feedback_category(categories)
    contribution = min(MALICIOUS_FEEDBACK_CAP, MALICIOUS_FEEDBACK_POINTS)
    user_feedback.score += contribution
    user_feedback.status = "warning"
    user_feedback.short_summary = "User-marked malicious indicators matched this message."
    for index, match in enumerate(malicious_matches):
        user_feedback.checks.append(
            Check(
                name="User-marked malicious indicator",
                result="match",
                points=contribution if index == 0 else 0,
                explanation="This indicator was previously marked malicious by the user.",
                evidence_summary=f"{match.indicator_type}: {match.indicator_value}",
                indicator_type=match.indicator_type,
                indicator_value=match.indicator_value,
            )
        )
    adjustments.append(
        AppliedAdjustment(
            type="malicious_feedback_match",
            points=contribution,
            explanation="One or more user-marked malicious indicators matched this message. Contribution was capped to avoid duplicate inflation.",
        )
    )


def _apply_safe_browsing_trust_conflicts(
    categories: dict[str, CategoryDetail],
    trusted_matches: list[FeedbackIndicator],
    adjustments: list[AppliedAdjustment],
) -> None:
    if "external_intel" not in categories:
        return
    trusted_values = {(match.indicator_type, match.indicator_value) for match in trusted_matches}
    for check in categories["external_intel"].checks:
        if check.name != "Safe Browsing match" or not check.indicator_value:
            continue
        normalized_url = normalize_indicator("url", check.indicator_value)
        if ("url", normalized_url) in trusted_values:
            adjustments.append(
                AppliedAdjustment(
                    type="trusted_indicator_overridden_by_external_intel",
                    points=0,
                    explanation="User marked this indicator as trusted, but external threat intelligence reported it as unsafe.",
                    indicator_type="url",
                    indicator_value=normalized_url,
                )
            )


def _remaining_heuristic_score(categories: dict[str, CategoryDetail]) -> int:
    total = 0
    for key, category in categories.items():
        if key in {"external_intel", "user_feedback"}:
            continue
        for check in category.checks:
            if check.is_critical or check.name in MAJOR_AUTH_FAILURES:
                continue
            total += max(0, check.points)
    return total


def _ensure_user_feedback_category(categories: dict[str, CategoryDetail]) -> CategoryDetail:
    if "user_feedback" not in categories:
        categories["user_feedback"] = CategoryDetail(
            title=CATEGORY_TITLES["user_feedback"],
            score=0,
            max_score=MALICIOUS_FEEDBACK_CAP,
            status="passed",
            short_summary="No user feedback indicators matched this message.",
            checks=[],
            feedback_actions=[],
        )
    category = categories["user_feedback"]
    category.status = "warning" if category.score else "passed"
    category.short_summary = "User feedback indicators affected this analysis." if category.score else category.short_summary
    return category


def _capped_score(category: CategoryDetail) -> int:
    if category.title == CATEGORY_TITLES["external_intel"]:
        return min(category.max_score, sum(max(0, check.points) for check in category.checks))
    return min(category.max_score, sum(max(0, check.points) for check in category.checks))


def _domain_for_link_check(check: Check) -> str | None:
    if not check.indicator_value:
        return None
    if check.indicator_type == "link_domain":
        return normalize_indicator("link_domain", check.indicator_value)
    if check.indicator_type == "url":
        return domain_for_url_indicator(check.indicator_value)
    return None


def _zero_score_summary(category: CategoryDetail) -> str:
    if category.title == CATEGORY_TITLES["links"]:
        return "No active local URL heuristic points remain after trusted feedback adjustments."
    if category.title == CATEGORY_TITLES["sender_auth"]:
        return "No active sender identity heuristic points remain after trusted feedback adjustments."
    return category.short_summary
