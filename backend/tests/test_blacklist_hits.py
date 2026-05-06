from app.feedback.repository import FeedbackRepository
from app.feedback.service import FeedbackService
from app.models import AnalyzeRequest, FeedbackRequest
from app.scoring.engine import analyze_email


def test_malicious_feedback_adds_capped_score_and_lists_repeated_matches(tmp_path) -> None:
    service = FeedbackService(FeedbackRepository(f"sqlite:///{tmp_path / 'feedback.db'}"))
    for indicator_type, value, source in [
        ("sender_email", "attacker@example.com", "sender_auth"),
        ("sender_domain", "example.com", "sender_auth"),
        ("url", "http://bad.example/login", "links"),
        ("link_domain", "bad.example", "links"),
    ]:
        service.save_feedback(
            FeedbackRequest(
                indicator_type=indicator_type,
                indicator_value=value,
                label="malicious",
                source_category=source,
            )
        )

    result = analyze_email(
        AnalyzeRequest(
            sender_email="attacker@example.com",
            body_text="Open http://bad.example/login",
            urls=[{"url": "http://bad.example/login"}],
        ),
        feedback_service=service,
    )

    assert result.category_scores["user_feedback"] == 50
    assert len(result.categories["user_feedback"].checks) >= 3
    assert sum(check.points for check in result.categories["user_feedback"].checks) == 50
    assert any(item.type == "malicious_feedback_match" for item in result.applied_adjustments)


def test_malicious_domain_is_not_suppressed_by_trusted_url(tmp_path) -> None:
    service = FeedbackService(FeedbackRepository(f"sqlite:///{tmp_path / 'feedback.db'}"))
    service.save_feedback(
        FeedbackRequest(
            indicator_type="url",
            indicator_value="http://bad.example/login",
            label="trusted",
            source_category="links",
        )
    )
    service.save_feedback(
        FeedbackRequest(
            indicator_type="link_domain",
            indicator_value="bad.example",
            label="malicious",
            source_category="links",
        )
    )

    result = analyze_email(
        AnalyzeRequest(
            sender_email="sender@example.com",
            body_text="Login at http://bad.example/login",
            urls=[{"url": "http://bad.example/login", "surrounding_text": "login"}],
        ),
        feedback_service=service,
    )

    assert result.category_scores["user_feedback"] == 50
    assert any(item.type == "malicious_feedback_match" for item in result.applied_adjustments)
