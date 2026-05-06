from app.feedback.repository import FeedbackRepository
from app.feedback.service import FeedbackService
from app.models import AnalyzeRequest, FeedbackRequest
from app.scoring.engine import analyze_email


def service_for(tmp_path) -> FeedbackService:
    return FeedbackService(FeedbackRepository(f"sqlite:///{tmp_path / 'feedback.db'}"))


def save(service: FeedbackService, indicator_type: str, value: str, label: str, source: str = "sender_auth") -> None:
    service.save_feedback(
        FeedbackRequest(
            indicator_type=indicator_type,
            indicator_value=value,
            label=label,
            source_category=source,
        )
    )


def test_trusted_sender_sets_sender_identity_score_to_zero_and_reduces_remaining(tmp_path) -> None:
    service = service_for(tmp_path)
    request = AnalyzeRequest(
        sender_email="support@example.com",
        sender_display_name="PayPal Support",
        reply_to="case@example.net",
        subject="Urgent password reset",
        body_text="Verify your password today at http://example.net/login",
        urls=[{"url": "http://example.net/login", "surrounding_text": "verify password"}],
    )
    baseline = analyze_email(request, feedback_service=service)
    save(service, "sender_email", "support@example.com", "trusted")

    adjusted = analyze_email(request, feedback_service=service)

    assert baseline.categories["sender_auth"].score > 0
    assert adjusted.categories["sender_auth"].score == 0
    assert adjusted.final_score < baseline.final_score
    assert any(item.type == "trusted_sender_remaining_heuristic_reduction" for item in adjusted.applied_adjustments)


def test_trusted_sender_does_not_suppress_safe_browsing_match(tmp_path) -> None:
    class FakeSafeBrowsing:
        def check_urls(self, urls: list[str]) -> dict[str, list[str]]:
            return {urls[0]: ["SOCIAL_ENGINEERING"]}

    service = service_for(tmp_path)
    save(service, "sender_email", "support@example.com", "trusted")
    request = AnalyzeRequest(
        sender_email="support@example.com",
        body_text="Review http://bad.example/login",
        urls=[{"url": "http://bad.example/login"}],
    )

    result = analyze_email(request, feedback_service=service, safe_browsing_client=FakeSafeBrowsing())

    assert result.categories["external_intel"].score == 50
    assert any(check.name == "Safe Browsing match" for check in result.categories["external_intel"].checks)


def test_trusted_url_reduces_local_url_heuristic_score(tmp_path) -> None:
    service = service_for(tmp_path)
    request = AnalyzeRequest(
        sender_email="sender@example.com",
        subject="Account security",
        body_text="Login at http://bit.ly/reset",
        urls=[{"url": "http://bit.ly/reset", "surrounding_text": "login security"}],
    )
    baseline = analyze_email(request, feedback_service=service)
    save(service, "url", "http://bit.ly/reset", "trusted", "links")

    adjusted = analyze_email(request, feedback_service=service)

    assert adjusted.categories["links"].score < baseline.categories["links"].score
    assert any(item.type == "trusted_url_or_domain_reduction" for item in adjusted.applied_adjustments)


def test_trusted_link_domain_recalculates_links_score_and_zeroes_matching_checks(tmp_path) -> None:
    service = service_for(tmp_path)
    request = AnalyzeRequest(
        sender_email="sender@example.com",
        subject="Account security",
        body_text="Login at http://bit.ly/reset",
        urls=[{"url": "http://bit.ly/reset", "surrounding_text": "login security"}],
    )
    baseline = analyze_email(request, feedback_service=service)
    save(service, "link_domain", "bit.ly", "trusted", "links")

    adjusted = analyze_email(request, feedback_service=service)
    link_checks = adjusted.categories["links"].checks
    trusted_zero_checks = [
        check for check in link_checks
        if "trusted by the user" in check.explanation
    ]

    assert baseline.categories["links"].score > 0
    assert adjusted.categories["links"].score < baseline.categories["links"].score
    assert adjusted.category_scores["links"] == adjusted.categories["links"].score
    assert all(check.points == 0 for check in trusted_zero_checks)
    assert adjusted.final_score < baseline.final_score


def test_trusted_exact_url_recalculates_links_score(tmp_path) -> None:
    service = service_for(tmp_path)
    request = AnalyzeRequest(
        sender_email="sender@example.com",
        subject="Account security",
        body_text="Login at http://example.net/reset",
        urls=[{"url": "http://example.net/reset?token=secret#frag", "surrounding_text": "login security"}],
    )
    baseline = analyze_email(request, feedback_service=service)
    save(service, "url", "http://example.net/reset?token=secret#frag", "trusted", "links")

    adjusted = analyze_email(request, feedback_service=service)

    assert adjusted.categories["links"].score < baseline.categories["links"].score
    assert adjusted.category_scores["links"] == adjusted.categories["links"].score
    assert any(
        check.points == 0 and "trusted by the user" in check.explanation
        for check in adjusted.categories["links"].checks
    )
