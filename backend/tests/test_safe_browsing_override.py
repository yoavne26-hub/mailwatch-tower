from app.feedback.repository import FeedbackRepository
from app.feedback.service import FeedbackService
from app.models import AnalyzeRequest, FeedbackRequest
from app.scoring.engine import analyze_email


class FakeSafeBrowsingMatch:
    def check_urls(self, urls: list[str]) -> dict[str, list[str]]:
        return {urls[0]: ["MALWARE"]}


def test_missing_safe_browsing_key_marks_enrichment_not_available(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    service = FeedbackService(FeedbackRepository(f"sqlite:///{tmp_path / 'feedback.db'}"))

    result = analyze_email(
        AnalyzeRequest(urls=[{"url": "https://example.com/login"}]),
        feedback_service=service,
    )

    check = result.categories["external_intel"].checks[0]
    assert check.result == "not_available"
    assert result.categories["external_intel"].score == 0


def test_safe_browsing_wins_over_trusted_url(tmp_path) -> None:
    service = FeedbackService(FeedbackRepository(f"sqlite:///{tmp_path / 'feedback.db'}"))
    service.save_feedback(
        FeedbackRequest(
            indicator_type="url",
            indicator_value="http://bad.example/login",
            label="trusted",
            source_category="links",
        )
    )

    result = analyze_email(
        AnalyzeRequest(urls=[{"url": "http://bad.example/login", "surrounding_text": "login"}]),
        feedback_service=service,
        safe_browsing_client=FakeSafeBrowsingMatch(),
    )

    assert result.categories["external_intel"].score == 50
    assert any(item.type == "trusted_indicator_overridden_by_external_intel" for item in result.applied_adjustments)
