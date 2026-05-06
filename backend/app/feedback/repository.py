"""SQLite repository for feedback indicators."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Iterable

from app.config import get_settings
from app.feedback.normalization import indicator_hash, normalize_indicator
from app.models import FeedbackLabel, IndicatorType
from app.storage.database import get_connection


@dataclass(frozen=True)
class FeedbackIndicator:
    user_scope: str
    indicator_type: IndicatorType
    indicator_value: str
    indicator_value_hash: str
    label: FeedbackLabel
    source_category: str
    hit_count: int


class FeedbackRepository:
    """SQLite-backed feedback repository."""

    def __init__(self, database_url: str | None = None) -> None:
        self.database_url = database_url

    def save(
        self,
        *,
        user_scope: str,
        indicator_type: IndicatorType,
        indicator_value: str,
        label: FeedbackLabel,
        source_category: str,
    ) -> FeedbackIndicator:
        normalized = normalize_indicator(indicator_type, indicator_value)
        value_hash = indicator_hash(normalized)
        now = _now()
        with get_connection(self.database_url) as connection:
            connection.execute(
                """
                INSERT INTO feedback_indicators (
                    user_scope, indicator_type, indicator_value, indicator_value_hash,
                    label, source_category, created_at, last_seen_at, hit_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(user_scope, indicator_type, indicator_value_hash)
                DO UPDATE SET
                    indicator_value = excluded.indicator_value,
                    label = excluded.label,
                    source_category = excluded.source_category,
                    last_seen_at = excluded.last_seen_at,
                    hit_count = feedback_indicators.hit_count + 1
                """,
                (
                    user_scope,
                    indicator_type,
                    normalized,
                    value_hash,
                    label,
                    source_category,
                    now,
                    now,
                ),
            )
            connection.commit()
        return self.get(user_scope, indicator_type, normalized)  # type: ignore[return-value]

    def get(
        self,
        user_scope: str,
        indicator_type: IndicatorType,
        indicator_value: str,
    ) -> FeedbackIndicator | None:
        normalized = normalize_indicator(indicator_type, indicator_value)
        value_hash = indicator_hash(normalized)
        with get_connection(self.database_url) as connection:
            row = connection.execute(
                """
                SELECT user_scope, indicator_type, indicator_value, indicator_value_hash,
                       label, source_category, hit_count
                FROM feedback_indicators
                WHERE user_scope = ? AND indicator_type = ? AND indicator_value_hash = ?
                """,
                (user_scope, indicator_type, value_hash),
            ).fetchone()
        if row is None:
            return None
        return FeedbackIndicator(
            user_scope=row["user_scope"],
            indicator_type=row["indicator_type"],
            indicator_value=row["indicator_value"],
            indicator_value_hash=row["indicator_value_hash"],
            label=row["label"],
            source_category=row["source_category"],
            hit_count=row["hit_count"],
        )

    def find_matches(
        self,
        *,
        user_scope: str,
        indicators: Iterable[tuple[IndicatorType, str]],
    ) -> list[FeedbackIndicator]:
        matches: list[FeedbackIndicator] = []
        seen: set[tuple[str, str]] = set()
        for indicator_type, value in indicators:
            normalized = normalize_indicator(indicator_type, value)
            key = (indicator_type, indicator_hash(normalized))
            if key in seen:
                continue
            seen.add(key)
            indicator = self.get(user_scope, indicator_type, normalized)
            if indicator is not None:
                matches.append(indicator)
        self.record_hits(matches)
        return matches

    def record_hits(self, indicators: list[FeedbackIndicator]) -> None:
        if not indicators:
            return
        now = _now()
        with get_connection(self.database_url) as connection:
            for indicator in indicators:
                connection.execute(
                    """
                    UPDATE feedback_indicators
                    SET last_seen_at = ?, hit_count = hit_count + 1
                    WHERE user_scope = ? AND indicator_type = ? AND indicator_value_hash = ?
                    """,
                    (
                        now,
                        indicator.user_scope,
                        indicator.indicator_type,
                        indicator.indicator_value_hash,
                    ),
                )
            connection.commit()


def default_repository() -> FeedbackRepository:
    return FeedbackRepository(get_settings().database_url)


def _now() -> str:
    return datetime.now(UTC).isoformat()
