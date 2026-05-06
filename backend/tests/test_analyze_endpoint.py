from fastapi.testclient import TestClient

from app.main import app


def test_health_returns_documented_payload() -> None:
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "mailwatch-tower-backend",
        "version": "1.0.0",
    }


def test_analyze_returns_ui_ready_fields(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'feedback.db'}")
    client = TestClient(app)
    payload = {
        "message_id": "msg-1",
        "sender_email": "security@paypa1-security.xyz",
        "sender_display_name": "PayPal Security",
        "reply_to": "approval@example.net",
        "return_path": "bounce@example.net",
        "subject": "Urgent password reset",
        "body_text": "Dear customer, verify your password today at http://198.51.100.24/login",
        "urls": [{"url": "http://198.51.100.24/login", "surrounding_text": "verify password"}],
        "attachments": [{"filename": "invoice.pdf.exe", "mime_type": "application/octet-stream"}],
        "headers": {"Authentication-Results": "spf=fail dkim=fail dmarc=fail"},
    }

    response = client.post("/analyze", json=payload)
    data = response.json()

    assert response.status_code == 200
    for field in [
        "analysis_id",
        "message_fingerprint",
        "final_score",
        "base_score",
        "verdict",
        "summary",
        "category_scores",
        "applied_adjustments",
        "categories",
        "recommended_actions",
    ]:
        assert field in data
    for category in ["sender_auth", "links", "attachments", "content", "external_intel"]:
        assert category in data["categories"]
        detail = data["categories"][category]
        for field in ["title", "score", "max_score", "status", "short_summary", "checks", "feedback_actions"]:
            assert field in detail
    first_check = data["categories"]["sender_auth"]["checks"][0]
    assert {"name", "result", "points", "explanation", "evidence_summary"} <= set(first_check)


def test_analyze_missing_fields_and_malformed_urls_do_not_crash(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'feedback.db'}")
    client = TestClient(app)

    response = client.post("/analyze", json={"urls": [{"url": "http://[not-valid"}]})

    assert response.status_code == 200
    data = response.json()
    assert 0 <= data["final_score"] <= 100
    assert data["categories"]["external_intel"]["checks"][0]["result"] == "not_available"
