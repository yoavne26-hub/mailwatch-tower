"""Configuration helpers for the MailWatch Tower backend."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Runtime settings loaded from environment variables."""

    environment: str = "local"
    max_body_chars: int = 20_000
    max_urls: int = 50
    max_attachments: int = 30


def get_settings() -> Settings:
    """Load settings without introducing external configuration dependencies."""
    def read_positive_int(name: str, default: int) -> int:
        raw_value = os.getenv(name)
        if raw_value is None:
            return default
        try:
            return max(0, int(raw_value))
        except ValueError:
            return default

    return Settings(
        environment=os.getenv("MAILWATCH_ENV", "local"),
        max_body_chars=read_positive_int("MAX_BODY_CHARS", 20_000),
        max_urls=read_positive_int("MAX_URLS", 50),
        max_attachments=read_positive_int("MAX_ATTACHMENTS", 30),
    )
