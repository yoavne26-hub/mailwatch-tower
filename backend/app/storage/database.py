"""SQLite database helpers for feedback indicator storage."""

import sqlite3
from pathlib import Path
from urllib.parse import urlparse

from app.config import get_settings


def database_path(database_url: str | None = None) -> str:
    """Return a local SQLite path from a sqlite:/// URL."""
    url = database_url or get_settings().database_url
    if url == ":memory:" or url == "sqlite:///:memory:":
        return ":memory:"
    if not url.startswith("sqlite:///"):
        raise ValueError("Only sqlite:/// DATABASE_URL values are supported in the MVP.")
    parsed = urlparse(url)
    path = parsed.path.lstrip("/")
    return path or "mailwatch.db"


def get_connection(database_url: str | None = None) -> sqlite3.Connection:
    """Create a SQLite connection and initialize required tables."""
    path = database_path(database_url)
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    initialize_database(connection)
    return connection


def initialize_database(connection: sqlite3.Connection) -> None:
    """Create feedback tables if missing."""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS feedback_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_scope TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            indicator_value_hash TEXT NOT NULL,
            label TEXT NOT NULL,
            source_category TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            hit_count INTEGER NOT NULL DEFAULT 1,
            UNIQUE(user_scope, indicator_type, indicator_value_hash)
        )
        """
    )
    connection.commit()
