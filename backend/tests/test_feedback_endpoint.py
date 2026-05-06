from fastapi.testclient import TestClient

from app.main import app


def test_feedback_saves_indicator(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'feedback.db'}")
    client = TestClient(app)

    response = client.post(
        "/feedback",
        json={
            "message_fingerprint": "abc",
            "indicator_type": "sender_email",
            "indicator_value": "Sender@Example.com",
            "label": "trusted",
            "source_category": "sender_auth",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "saved": True,
        "message": "Sender trusted.",
        "recommended_reanalysis": True,
    }
