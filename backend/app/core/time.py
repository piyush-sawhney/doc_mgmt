"""UTC timestamps in the exact forms the vault contracts use."""

from __future__ import annotations

from datetime import UTC, datetime


def now_utc() -> datetime:
    """Timezone-aware UTC now. Never use a naive datetime in storage."""
    return datetime.now(UTC)


def format_seconds(moment: datetime) -> str:
    """``2026-10-28T10:12:03Z`` — manifest, lock, dump names."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_millis(moment: datetime) -> str:
    """``2026-10-28T11:04:19.221Z`` — audit entries."""
    moment = moment.astimezone(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def parse_timestamp(text: str) -> datetime:
    """Parse both accepted ISO-8601 forms and require a timezone."""
    normalised = text[:-1] + "+00:00" if text.endswith("Z") else text
    moment = datetime.fromisoformat(normalised)
    if moment.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return moment.astimezone(UTC)
