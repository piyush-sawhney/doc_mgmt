"""ACL administration endpoints."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Cookie, Header, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as OrmSession

from app.core.errors import DocVaultError
from app.crypto.keys import VaultKeys
from app.db.enums import AclEffect, AclObject, AclSubject, RoleName
from app.db.models.entities import Entity
from app.services import acl, auth
from app.services.audit import append_event
from app.vault.session import VaultManager

router = APIRouter(prefix="/api/v1", tags=["access control"])
Capability = Literal["view", "read", "write", "delete", "manage_acl", "print"]


class AclGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject_type: AclSubject
    subject_id: UUID
    capabilities: tuple[Capability, ...] = Field(min_length=1)
    effect: AclEffect = AclEffect.ALLOW


class AclReplaceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entries: tuple[AclGrantRequest, ...]


class AclEntryResponse(BaseModel):
    subject_type: AclSubject
    subject_id: UUID
    capabilities: tuple[str, ...]
    effect: AclEffect


class AclResponse(BaseModel):
    entries: tuple[AclEntryResponse, ...]


class EffectiveAccessEntry(BaseModel):
    user_id: UUID
    capabilities: tuple[str, ...]


class EffectiveAccessResponse(BaseModel):
    entries: tuple[EffectiveAccessEntry, ...]


def _engine(request: Request) -> Engine:
    engine = getattr(request.app.state, "db_engine", None)
    if not isinstance(engine, Engine):
        raise DocVaultError("DB_UNAVAILABLE", detail="The database is not configured.")
    return engine


def _keys(request: Request) -> VaultKeys:
    vault = getattr(request.app.state, "vault", None)
    if not isinstance(vault, VaultManager):
        raise DocVaultError("NOT_READY", detail="The vault is not open.")
    return vault.keys


def _source_ip(request: Request) -> str:
    if request.client is None:
        raise DocVaultError("BAD_REQUEST", detail="The request has no source address.")
    return request.client.host


def _actor(
    session: OrmSession,
    keys: VaultKeys,
    token: str | None,
    csrf: str | None,
    *,
    mutate: bool,
) -> auth.AuthenticatedSession:
    actor = auth.authenticate(session, keys, token)
    if mutate:
        auth.verify_csrf(session, token, csrf)
    return actor


def _require_admin(
    session: OrmSession,
    actor: auth.AuthenticatedSession,
    *,
    object_type: str,
    object_id: UUID,
    source_ip: str,
) -> None:
    if RoleName.ADMIN.value not in actor.roles:
        bind = session.get_bind()
        with OrmSession(bind=bind) as audit_session, audit_session.begin():
            append_event(
                audit_session,
                action="access.deny",
                object_type=object_type,
                object_id=object_id,
                actor_id=actor.user_id,
                outcome="deny",
                source_ip=source_ip,
                detail={"required_role": RoleName.ADMIN.value},
            )
        raise DocVaultError("FORBIDDEN", detail="Administrator role is required.")
    append_event(
        session,
        action="access.allow",
        object_type=object_type,
        object_id=object_id,
        actor_id=actor.user_id,
        source_ip=source_ip,
        detail={"required_role": RoleName.ADMIN.value},
    )


def _entry_response(grant: acl.Grant) -> AclEntryResponse:
    names = tuple(name for name, bit in acl.CAPABILITY_BITS.items() if grant.capabilities & bit)
    return AclEntryResponse(
        subject_type=grant.subject_type,
        subject_id=grant.subject_id,
        capabilities=names,
        effect=grant.effect,
    )


def _acl_response(grants: tuple[acl.Grant, ...]) -> AclResponse:
    return AclResponse(entries=tuple(_entry_response(grant) for grant in grants))


def _to_grants(entries: tuple[AclGrantRequest, ...]) -> tuple[acl.Grant, ...]:
    return tuple(
        acl.Grant(
            subject_type=entry.subject_type,
            subject_id=entry.subject_id,
            capabilities=acl.capability_mask(entry.capabilities),
            effect=entry.effect,
        )
        for entry in entries
    )


@router.get("/documents/{document_id}/acl", response_model=AclResponse)
def get_document_acl(
    document_id: UUID,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> AclResponse:
    """Read a document ACL after checking manage_acl."""
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, _keys(request), token, None, mutate=False)
        acl.require_document(
            session,
            actor.user_id,
            document_id,
            acl.MANAGE_ACL,
            source_ip=_source_ip(request),
        )
        grants = acl.list_acl(
            session,
            object_type=AclObject.DOCUMENT,
            object_id=document_id,
        )
    return _acl_response(grants)


@router.put("/documents/{document_id}/acl", response_model=AclResponse)
def replace_document_acl(
    document_id: UUID,
    body: AclReplaceRequest,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> AclResponse:
    """Replace a document ACL in the same transaction as its audit event."""
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, _keys(request), token, csrf, mutate=True)
        acl.require_document(
            session,
            actor.user_id,
            document_id,
            acl.MANAGE_ACL,
            source_ip=_source_ip(request),
        )
        grants = acl.replace_acl(
            session,
            object_type=AclObject.DOCUMENT,
            object_id=document_id,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
            grants=_to_grants(body.entries),
        )
    return _acl_response(grants)


@router.get("/documents/{document_id}/effective-access", response_model=EffectiveAccessResponse)
def get_document_effective_access(
    document_id: UUID,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> EffectiveAccessResponse:
    """Return bounded per-user effective access for administrators and ACL managers."""
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, _keys(request), token, None, mutate=False)
        document = acl.require_document(
            session,
            actor.user_id,
            document_id,
            acl.MANAGE_ACL,
            source_ip=_source_ip(request),
        )
        effective = acl.effective_access_for_document(session, document)
    entries = tuple(
        EffectiveAccessEntry(
            user_id=user_id,
            capabilities=tuple(
                name for name, bit in acl.CAPABILITY_BITS.items() if capabilities & bit
            ),
        )
        for user_id, capabilities in effective
    )
    return EffectiveAccessResponse(entries=entries)


@router.get("/entities/{entity_id}/acl", response_model=AclResponse)
def get_entity_acl(
    entity_id: UUID,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> AclResponse:
    """Read an entity ACL for an administrator."""
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, _keys(request), token, None, mutate=False)
        _require_admin(
            session,
            actor,
            object_type="entity",
            object_id=entity_id,
            source_ip=_source_ip(request),
        )
        if session.get(Entity, entity_id) is None:
            raise DocVaultError("NOT_FOUND")
        grants = acl.list_acl(
            session,
            object_type=AclObject.ENTITY,
            object_id=entity_id,
        )
    return _acl_response(grants)


@router.get("/entities/{entity_id}/effective-access", response_model=EffectiveAccessResponse)
def get_entity_effective_access(
    entity_id: UUID,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> EffectiveAccessResponse:
    """Return each user's effective entity capabilities to administrators."""
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, _keys(request), token, None, mutate=False)
        _require_admin(
            session,
            actor,
            object_type="entity",
            object_id=entity_id,
            source_ip=_source_ip(request),
        )
        entity = session.get(Entity, entity_id)
        if entity is None:
            raise DocVaultError("NOT_FOUND")
        effective = acl.effective_access_for_entity(session, entity)
    entries = tuple(
        EffectiveAccessEntry(
            user_id=user_id,
            capabilities=tuple(
                name for name, bit in acl.CAPABILITY_BITS.items() if capabilities & bit
            ),
        )
        for user_id, capabilities in effective
    )
    return EffectiveAccessResponse(entries=entries)


@router.put("/entities/{entity_id}/acl", response_model=AclResponse)
def replace_entity_acl(
    entity_id: UUID,
    body: AclReplaceRequest,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> AclResponse:
    """Replace an entity ACL; the service enforces administrator-only access."""
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, _keys(request), token, csrf, mutate=True)
        _require_admin(
            session,
            actor,
            object_type="entity",
            object_id=entity_id,
            source_ip=_source_ip(request),
        )
        grants = acl.replace_acl(
            session,
            object_type=AclObject.ENTITY,
            object_id=entity_id,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
            grants=_to_grants(body.entries),
        )
    return _acl_response(grants)
