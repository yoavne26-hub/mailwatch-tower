from app.feedback.repository import FeedbackRepository
from app.feedback.service import FeedbackService
from app.analyzers.enrichment_analyzer import SafeBrowsingClient
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
    assert check.name == "Google Safe Browsing"
    assert "SAFE_BROWSING_API_KEY" in check.explanation
    assert result.categories["external_intel"].score == 0


def test_no_urls_marks_safe_browsing_not_available(tmp_path) -> None:
    service = FeedbackService(FeedbackRepository(f"sqlite:///{tmp_path / 'feedback.db'}"))

    result = analyze_email(AnalyzeRequest(body_text="No links here."), feedback_service=service)

    check = result.categories["external_intel"].checks[0]
    assert check.result == "not_available"
    assert result.categories["external_intel"].score == 0


def test_safe_browsing_client_no_match(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {}

    def fake_post(url: str, json: dict[str, object], timeout: float) -> FakeResponse:
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("app.analyzers.enrichment_analyzer.httpx.post", fake_post)

    result = SafeBrowsingClient("test-key", timeout_seconds=3).check_urls(["https://example.com/login?token=secret"])

    assert result == {}
    assert "key=test-key" in str(captured["url"])
    assert captured["timeout"] == 3
    threat_info = captured["json"]["threatInfo"]  # type: ignore[index]
    assert threat_info["threatEntries"] == [{"url": "https://example.com/login?token=secret"}]


def test_safe_browsing_no_match_category_avoids_safe_language(tmp_path) -> None:
    class FakeSafeBrowsingNoMatch:
        def check_urls(self, urls: list[str]) -> dict[str, list[str]]:
            return {}

    service = FeedbackService(FeedbackRepository(f"sqlite:///{tmp_path / 'feedback.db'}"))

    result = analyze_email(
        AnalyzeRequest(urls=[{"url": "https://example.com/login"}]),
        feedback_service=service,
        safe_browsing_client=FakeSafeBrowsingNoMatch(),
    )

    check = result.categories["external_intel"].checks[0]
    assert check.result == "no_match"
    assert check.points == 0
    assert result.categories["external_intel"].score == 0
    assert " is safe" not in check.explanation.lower()
    assert "confirmed" not in check.explanation.lower()


def test_safe_browsing_match_increases_external_intel_and_final_score(tmp_path) -> None:
    service = FeedbackService(FeedbackRepository(f"sqlite:///{tmp_path / 'feedback.db'}"))
    baseline = analyze_email(
        AnalyzeRequest(urls=[{"url": "https://bad.example/login"}]),
        feedback_service=service,
    )

    result = analyze_email(
        AnalyzeRequest(urls=[{"url": "https://bad.example/login"}]),
        feedback_service=service,
        safe_browsing_client=FakeSafeBrowsingMatch(),
    )

    assert result.categories["external_intel"].score == 50
    assert result.category_scores["external_intel"] == result.categories["external_intel"].score
    assert result.final_score > baseline.final_score


def test_safe_browsing_api_error_does_not_fail_analysis(tmp_path) -> None:
    class FakeSafeBrowsingError:
        def check_urls(self, urls: list[str]) -> dict[str, list[str]]:
            raise TimeoutError("timeout")

    service = FeedbackService(FeedbackRepository(f"sqlite:///{tmp_path / 'feedback.db'}"))

    result = analyze_email(
        AnalyzeRequest(urls=[{"url": "https://example.com/login"}]),
        feedback_service=service,
        safe_browsing_client=FakeSafeBrowsingError(),
    )

    check = result.categories["external_intel"].checks[0]
    assert check.result == "not_available"
    assert check.points == 0
    assert result.categories["external_intel"].score == 0


def test_safe_browsing_multiple_matches_are_capped(tmp_path) -> None:
    class FakeSafeBrowsingMultipleMatches:
        def check_urls(self, urls: list[str]) -> dict[str, list[str]]:
            return {
                "https://bad1.example/login": ["MALWARE/ANY_PLATFORM"],
                "https://bad2.example/login": ["SOCIAL_ENGINEERING/ANY_PLATFORM"],
            }

    service = FeedbackService(FeedbackRepository(f"sqlite:///{tmp_path / 'feedback.db'}"))

    result = analyze_email(
        AnalyzeRequest(
            urls=[
                {"url": "https://bad1.example/login"},
                {"url": "https://bad2.example/login"},
            ]
        ),
        feedback_service=service,
        safe_browsing_client=FakeSafeBrowsingMultipleMatches(),
    )

    assert result.categories["external_intel"].score == 50
    assert result.category_scores["external_intel"] == 50


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
    assert result.categories["links"].score == 0
    assert any(item.type == "trusted_indicator_overridden_by_external_intel" for item in result.applied_adjustments)


def test_safe_browsing_wins_over_trusted_link_domain(tmp_path) -> None:
    service = FeedbackService(FeedbackRepository(f"sqlite:///{tmp_path / 'feedback.db'}"))
    service.save_feedback(
        FeedbackRequest(
            indicator_type="link_domain",
            indicator_value="bad.example",
            label="trusted",
            source_category="links",
        )
    )

    result = analyze_email(
        AnalyzeRequest(urls=[{"url": "http://www.bad.example/login", "surrounding_text": "login"}]),
        feedback_service=service,
        safe_browsing_client=FakeSafeBrowsingMatch(),
    )

    assert result.categories["external_intel"].score == 50
    assert result.categories["links"].score == 0
    assert any(item.type == "trusted_indicator_overridden_by_external_intel" for item in result.applied_adjustments)
