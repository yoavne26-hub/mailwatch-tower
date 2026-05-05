import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "sample_emails"


def load_sample(name: str) -> dict:
    return json.loads((SAMPLES_DIR / name).read_text(encoding="utf-8"))


def test_analyze_safe_sample_returns_safe_or_low_risk() -> None:
    client = TestClient(app)

    response = client.post("/analyze", json=load_sample("safe_email.json"))
    data = response.json()

    assert response.status_code == 200
    assert data["verdict"] in {"Safe", "Low Risk"}
    assert 0 <= data["score"] <= 100
    assert "signals" in data
    assert "recommendations" in data
    assert "limitations" in data


def test_analyze_suspicious_sample_returns_suspicious_or_high_risk() -> None:
    client = TestClient(app)

    response = client.post("/analyze", json=load_sample("suspicious_email.json"))
    data = response.json()

    assert response.status_code == 200
    assert data["verdict"] in {"Suspicious", "High Risk"}
    assert data["score"] == data["raw_score"]


def test_analyze_dangerous_sample_is_capped_dangerous() -> None:
    client = TestClient(app)

    response = client.post("/analyze", json=load_sample("dangerous_email.json"))
    data = response.json()

    assert response.status_code == 200
    assert data["verdict"] == "Dangerous"
    assert data["score"] == 100
    assert data["raw_score"] > 100
    assert data["verdict_color"] == "#D93025"
    assert all("name" in signal for signal in data["signals"])
