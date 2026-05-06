"""Runtime configuration for the MailWatch Tower backend."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Backend settings loaded from environment variables."""

    app_env: str = "local"
    database_url: str = "sqlite:///mailwatch.db"
    safe_browsing_api_key: str | None = None
    log_level: str = "INFO"
    allowed_origins: str | None = None
    addon_shared_secret: str | None = None
    max_body_chars: int = 20_000
    max_subject_chars: int = 500
    max_urls: int = 50
    max_attachments: int = 30
    safe_browsing_max_urls: int = 50
    safe_browsing_timeout_seconds: float = 5.0
    default_user_scope: str = "local-demo"


def get_settings() -> Settings:
    """Load settings without requiring an external config package."""
    return Settings(
        app_env=os.getenv("APP_ENV", os.getenv("MAILWATCH_ENV", "local")),
        database_url=os.getenv("DATABASE_URL", "sqlite:///mailwatch.db"),
        safe_browsing_api_key=os.getenv("SAFE_BROWSING_API_KEY") or None,
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        allowed_origins=os.getenv("ALLOWED_ORIGINS") or None,
        addon_shared_secret=os.getenv("ADDON_SHARED_SECRET") or None,
        max_body_chars=_read_positive_int("MAX_BODY_CHARS", 20_000),
        max_subject_chars=_read_positive_int("MAX_SUBJECT_CHARS", 500),
        max_urls=_read_positive_int("MAX_URLS", 50),
        max_attachments=_read_positive_int("MAX_ATTACHMENTS", 30),
        safe_browsing_max_urls=_read_positive_int("SAFE_BROWSING_MAX_URLS", 50),
        safe_browsing_timeout_seconds=_read_positive_float("SAFE_BROWSING_TIMEOUT_SECONDS", 5.0),
        default_user_scope=os.getenv("USER_SCOPE", "local-demo"),
    )


def _read_positive_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return max(0, int(raw_value))
    except ValueError:
        return default


def _read_positive_float(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return max(0.1, float(raw_value))
    except ValueError:
        return default
