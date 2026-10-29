"""Auditor and administrator views of the audit trail and the vault.

The audit files are the authority for integrity; ``audit_events`` is the query
index written in the same transaction as the change (docs/03 §10, docs/07 §6).
These routes expose both without ever returning key material.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Cookie, Header, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as OrmSession

from app.core.errors import DocVaultError
from app.db import connect
from app.db.enums import AuditOutcome, RoleName
from app.db.models.operations import AuditEvent
from app.services import auth
from app.vault import audit
from app.vault.inspect import inspect
from app.vault.session import VaultManager

router = APIRouter(prefix="/api/v1", tags=["operations"])
MAX_PAGE = 200


class AuditEventResponse(BaseModel):
    seq: int
    ts: datetime
    actor_id: uuid.UUID | None
    action: str
    object_type: str
    object_id: uuid.UUID | None
    outcome: AuditOutcome
    source_ip: str | None
    detail: dict[str, object]
    file_month: str


class AuditListResponse(BaseModel):
    items: list[AuditEventResponse]
    total: int


class AuditVerifyResponse(BaseModel):
    ok: bool
    entries: int
    first_bad_seq: int | None
    detail: str


class VaultStatusResponse(BaseModel):
    vault_id: str
    display_name: str
    format_version: int
    schema_version: int
    key_fingerprint: str
    root: str
    size_bytes: int
    blob_count: int
    audit_entries: int
    last_dump: dict[str, str]
    last_dump_encrypted: bool | None
    postgres_version: str | None
    lock_state: str


def _engine(request: Request) -> Engine:
    engine = getattr(request.app.state, "db_engine", None)
    if not isinstance(engine, Engine):
        raise DocVaultError("DB_UNAVAILABLE", detail="The database is not configured.")
    return engine


def _vault(request: Request) -> VaultManager:
    vault = getattr(request.app.state, "vault", None)
    if not isinstance(vault, VaultManager):
        raise DocVaultError("NOT_READY", detail="The vault is not open.")
    return vault


def _actor(
    session: OrmSession,
    request: Request,
    token: str | None,
    *,
    roles: tuple[RoleName, ...],
) -> auth.AuthenticatedSession:
    actor = auth.authenticate(session, _vault(request).keys, token)
    if not any(role.value in actor.roles for role in roles):
        raise DocVaultError(
            "FORBIDDEN",
            detail=f"One of these roles is required: {', '.join(role.value for role in roles)}.",
        )
    return actor


def _event_response(event: AuditEvent) -> AuditEventResponse:
    return AuditEventResponse(
        seq=event.seq,
        ts=event.ts,
        actor_id=event.actor_id,
        action=event.action,
        object_type=event.object_type,
        object_id=event.object_id,
        outcome=event.outcome,
        source_ip=str(event.source_ip) if event.source_ip is not None else None,
        detail=event.detail,
        file_month=event.file_month,
    )


@router.get("/audit", response_model=AuditListResponse)
def list_audit(
    request: Request,
    actor_id: Annotated[uuid.UUID | None, Query()] = None,
    action: Annotated[str | None, Query(max_length=200)] = None,
    object_id: Annotated[uuid.UUID | None, Query()] = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> AuditListResponse:
    with OrmSession(_engine(request)) as session, session.begin():
        _actor(session, request, token, roles=(RoleName.ADMIN, RoleName.AUDITOR))
        statement = select(AuditEvent)
        if actor_id is not None:
            statement = statement.where(AuditEvent.actor_id == actor_id)
        if action is not None:
            statement = statement.where(AuditEvent.action == action)
        if object_id is not None:
            statement = statement.where(AuditEvent.object_id == object_id)
        if from_ is not None:
            statement = statement.where(AuditEvent.ts >= from_)
        if to is not None:
            statement = statement.where(AuditEvent.ts <= to)
        total = session.scalar(select(func.count()).select_from(statement.subquery())) or 0
        rows = session.scalars(
            statement.order_by(AuditEvent.seq.desc()).limit(limit).offset(offset)
        )
        return AuditListResponse(items=[_event_response(row) for row in rows], total=total)


@router.post("/audit/verify", response_model=AuditVerifyResponse)
def verify_audit(
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> AuditVerifyResponse:
    with OrmSession(_engine(request)) as session, session.begin():
        _actor(session, request, token, roles=(RoleName.ADMIN,))
        auth.verify_csrf(session, token, csrf)
    result = audit.verify_chain(_vault(request).paths.audit_dir)
    return AuditVerifyResponse(
        ok=result.ok,
        entries=result.entries,
        first_bad_seq=result.first_bad_seq,
        detail=result.detail,
    )


def _directory_size(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


@router.get("/vault/status", response_model=VaultStatusResponse)
def vault_status(
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> VaultStatusResponse:
    engine = _engine(request)
    with OrmSession(engine) as session, session.begin():
        _actor(session, request, token, roles=(RoleName.ADMIN,))
    vault = _vault(request)
    info = inspect(vault.paths.root)
    try:
        postgres = connect.server_info(engine).version
    except DocVaultError:
        postgres = None
    lock = info.lock.record
    lock_state = "free" if lock is None else "stale" if info.lock.stale else "held"
    encrypted = info.last_dump.get("encrypted")
    return VaultStatusResponse(
        vault_id=info.manifest.vault_id,
        display_name=info.manifest.display_name,
        format_version=info.manifest.format_version,
        schema_version=info.manifest.schema_version,
        key_fingerprint=info.manifest.key_fingerprint,
        root=str(info.paths.root),
        size_bytes=_directory_size(info.paths.root),
        blob_count=info.blob_count,
        audit_entries=info.audit_entries,
        last_dump=info.last_dump,
        last_dump_encrypted=None if encrypted is None else encrypted == "1",
        postgres_version=postgres,
        lock_state=lock_state,
    )
