"""Database audit writes that commit with the operation they describe."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import insert, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

from app.core.time import format_millis, now_utc
from app.crypto.canonical import canonical_json
from app.db.models.operations import AuditEvent

_AUDIT_LOCK = 0x444F435641554C54
_ZERO_HASH = bytes(32)


def append_event(
    connection: Connection | Session,
    *,
    action: str,
    object_type: str,
    actor_id: uuid.UUID | None = None,
    object_id: uuid.UUID | None = None,
    outcome: str = "allow",
    source_ip: str | None = None,
    detail: dict[str, Any] | None = None,
    moment: datetime | None = None,
) -> None:
    """Append one hash-chained row within the caller's transaction."""
    connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _AUDIT_LOCK})
    previous = connection.execute(
        select(AuditEvent.hash).order_by(AuditEvent.seq.desc()).limit(1)
    ).scalar_one_or_none()
    previous_hash = previous or _ZERO_HASH
    seq: int = connection.execute(
        text("SELECT nextval(pg_get_serial_sequence('audit_events', 'seq'))")
    ).scalar_one()
    timestamp = moment or now_utc()
    event: dict[str, Any] = {
        "seq": seq,
        "ts": format_millis(timestamp),
        "actor_id": str(actor_id) if actor_id else None,
        "action": action,
        "object_type": object_type,
        "object_id": str(object_id) if object_id else None,
        "outcome": outcome,
        "source_ip": str(source_ip) if source_ip is not None else None,
        "detail": detail or {},
        "prev_hash": previous_hash.hex(),
    }
    digest = hashlib.sha256(previous_hash.hex().encode("ascii") + canonical_json(event)).digest()
    connection.execute(
        insert(AuditEvent).values(
            seq=seq,
            ts=timestamp,
            actor_id=actor_id,
            action=action,
            object_type=object_type,
            object_id=object_id,
            outcome=outcome,
            source_ip=source_ip,
            detail=detail or {},
            prev_hash=previous_hash,
            hash=digest,
            file_month=timestamp.strftime("%Y-%m"),
        )
    )
