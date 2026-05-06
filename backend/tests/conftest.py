import pytest


@pytest.fixture(autouse=True)
def isolate_feedback_database(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'feedback.db'}")
