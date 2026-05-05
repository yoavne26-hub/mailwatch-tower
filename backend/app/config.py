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
    return Settings(
        environment=os.getenv("MAILWATCH_ENV", "local"),
        max_body_chars=int(os.getenv("MAX_BODY_CHARS", "20000")),
        max_urls=int(os.getenv("MAX_URLS", "50")),
        max_attachments=int(os.getenv("MAX_ATTACHMENTS", "30")),
    )

