"""Entity, person, and identifier API endpoints."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Cookie, Header, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as OrmSession

from app.core.errors import DocVaultError
from app.crypto.keys import VaultKeys, decrypt_column
from app.db.enums import EntityStatus, EntityType, Gender, PersonRole, RoleName
from app.db.models.documents import Document, DocumentEntityLink
from app.db.models.entities import Entity, Identifier
from app.services import acl, auth, entities
from app.services.audit import append_event
from app.vault.session import VaultManager

router = APIRouter(prefix="/api/v1", tags=["entities"])


class IdentifierCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id_type: str = Field(min_length=1, max_length=16)
    value: str = Field(min_length=1, max_length=256)
    label: str | None = Field(default=None, max_length=100)
    duplicate_ack_of: UUID | None = None


class EntityCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: EntityType
    legal_name: str = Field(min_length=1, max_length=300)
    display_name: str | None = Field(default=None, max_length=300)
    incorporation_date: date | None = None
    registered_address: str | None = Field(default=None, max_length=4000)
    contact: str | None = Field(default=None, max_length=1000)
    notes: str | None = Field(default=None, max_length=4000)
    identifiers: tuple[IdentifierCreate, ...] = Field(default=(), max_length=50)


class EntityPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    legal_name: str | None = Field(default=None, max_length=300)
    display_name: str | None = Field(default=None, max_length=300)
    incorporation_date: date | None = None
    registered_address: str | None = Field(default=None, max_length=4000)
    contact: str | None = Field(default=None, max_length=1000)
    notes: str | None = Field(default=None, max_length=4000)
    status: EntityStatus | None = None


class IdentifierResponse(BaseModel):
    id: UUID
    id_type: str
    value: str | None
    value_masked: str
    label: str | None
    verified: bool
    duplicate_ack_of: UUID | None
    row_version: int


class EntityResponse(BaseModel):
    id: UUID
    entity_type: EntityType
    legal_name: str
    display_name: str | None
    incorporation_date: date | None
    registered_address: str | None
    contact: str | None
    notes: str | None
    acl_mode: str
    status: EntityStatus
    row_version: int
    created_at: datetime
    updated_at: datetime
    identifiers: list[IdentifierResponse] = Field(default_factory=list)


class EntityListResponse(BaseModel):
    items: list[EntityResponse]
    next_cursor: str | None


class IdentifierListResponse(BaseModel):
    items: list[IdentifierResponse]


class IdentifierPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id_type: str | None = Field(default=None, min_length=1, max_length=16)
    value: str | None = Field(default=None, min_length=1, max_length=256)
    label: str | None = Field(default=None, max_length=100)


class PersonCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str = Field(min_length=1, max_length=300)
    role: PersonRole
    date_of_birth: date | None = None
    gender: Gender | None = None
    notes: str | None = Field(default=None, max_length=4000)
    effective_from: date | None = None
    effective_to: date | None = None


class PersonResponse(BaseModel):
    person_id: UUID
    full_name: str
    date_of_birth: date | None
    gender: Gender | None
    role: PersonRole
    effective_from: date | None
    effective_to: date | None


class PersonListResponse(BaseModel):
    items: list[PersonResponse]


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


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client is not None else None


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


def _if_match(value: str | None) -> int:
    if value is None:
        raise DocVaultError("PRECONDITION_REQUIRED")
    normalized = value.strip()
    if normalized.startswith("W/"):
        normalized = normalized[2:]
    if len(normalized) < 3 or normalized[0] != '"' or normalized[-1] != '"':
        raise DocVaultError("BAD_REQUEST", detail="If-Match must contain an ETag.")
    try:
        version = int(normalized[1:-1])
    except ValueError as exc:
        raise DocVaultError("BAD_REQUEST", detail="If-Match must contain a numeric ETag.") from exc
    if version < 1:
        raise DocVaultError("BAD_REQUEST", detail="If-Match must be a positive version.")
    return version


def _set_etag(response: Response, version: int) -> None:
    response.headers["ETag"] = f'W/"{version}"'


def _entity_response(session: OrmSession, record: Entity, keys: VaultKeys) -> EntityResponse:
    data = entities.entity_data(record, keys)
    data["identifiers"] = [
        entities.identifier_data(identifier, keys)
        for identifier in entities.list_identifiers(session, record.id)
    ]
    return EntityResponse.model_validate(data)


def _entity_query(
    session: OrmSession,
    actor_id: UUID,
    *,
    include_deleted: bool,
    cursor: UUID | None,
    entity_types: tuple[EntityType, ...],
    status: EntityStatus | None,
) -> list[Entity]:
    statement = acl.visible_entities(session, actor_id, include_deleted=include_deleted).order_by(
        Entity.created_at.desc(), Entity.id.desc()
    )
    if cursor is not None:
        cursor_record = session.get(Entity, cursor)
        if cursor_record is None:
            raise DocVaultError("BAD_REQUEST", detail="The pagination cursor is invalid.")
        statement = statement.where(
            (Entity.created_at < cursor_record.created_at)
            | ((Entity.created_at == cursor_record.created_at) & (Entity.id < cursor_record.id))
        )
    if entity_types:
        statement = statement.where(Entity.entity_type.in_(entity_types))
    if status is not None:
        statement = statement.where(Entity.status == status)
    return list(session.execute(statement.limit(2001)).scalars())


@router.get("/entities", response_model=EntityListResponse)
def list_entities(
    request: Request,
    response: Response,
    q: Annotated[str | None, Query(max_length=128)] = None,
    entity_type: Annotated[tuple[EntityType, ...], Query(alias="type")] = (),
    status: EntityStatus | None = None,
    include_deleted: bool = False,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    cursor: UUID | None = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> EntityListResponse:
    """Return bounded, ACL-filtered entities with masked identifiers."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, None, mutate=False)
        if include_deleted and RoleName.ADMIN.value not in actor.roles:
            raise DocVaultError(
                "FORBIDDEN", detail="Only administrators may include deleted entities."
            )
        records = _entity_query(
            session,
            actor.user_id,
            include_deleted=include_deleted,
            cursor=cursor,
            entity_types=entity_type,
            status=status,
        )
        if q:
            prefix = q.strip().casefold()
            filtered: list[Entity] = []
            for row in records[:2000]:
                values = entities.entity_data(row, keys)
                display = values["display_name"]
                legal = values["legal_name"]
                if (isinstance(display, str) and display.casefold().startswith(prefix)) or (
                    isinstance(legal, str) and legal.casefold().startswith(prefix)
                ):
                    filtered.append(row)
            records = filtered
        page = records[:limit]
        next_cursor = str(page[-1].id) if len(records) > limit and page else None
    if next_cursor:
        response.headers["Link"] = (
            f'</api/v1/entities?cursor={next_cursor}&limit={limit}>; rel="next"'
        )
    return EntityListResponse(
        items=[_entity_response(session, row, keys) for row in page],
        next_cursor=next_cursor,
    )


@router.post("/entities", response_model=EntityResponse, status_code=201)
def create_entity(
    body: EntityCreate,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> EntityResponse:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, csrf, mutate=True)
        if not {RoleName.ADMIN.value, RoleName.EDITOR.value}.intersection(actor.roles):
            raise DocVaultError("FORBIDDEN", detail="The write capability is required.")
        record = entities.create_entity(
            session,
            keys,
            actor_id=actor.user_id,
            entity_type=body.entity_type,
            legal_name=body.legal_name,
            display_name=body.display_name,
            incorporation_date=body.incorporation_date,
            registered_address=body.registered_address,
            contact=body.contact,
            notes=body.notes,
            identifiers=tuple(item.model_dump(exclude_none=True) for item in body.identifiers),
            source_ip=_source_ip(request),
        )
        _set_etag(response, record.row_version)
        response.headers["Location"] = f"/api/v1/entities/{record.id}"
        return _entity_response(session, record, keys)


@router.get("/entities/{entity_id}", response_model=EntityResponse)
def get_entity(
    entity_id: UUID,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> EntityResponse:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, None, mutate=False)
        record = acl.require_entity(
            session, actor.user_id, entity_id, acl.VIEW, source_ip=_source_ip(request)
        )
        result = _entity_response(session, record, keys)
        _set_etag(response, record.row_version)
    return result


@router.patch("/entities/{entity_id}", response_model=EntityResponse)
def patch_entity(
    entity_id: UUID,
    body: EntityPatch,
    request: Request,
    response: Response,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> EntityResponse:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, csrf, mutate=True)
        acl.require_entity(
            session, actor.user_id, entity_id, acl.WRITE, source_ip=_source_ip(request)
        )
        record = entities.patch_entity(
            session,
            keys,
            entity_id,
            actor.user_id,
            _if_match(if_match),
            body.model_dump(exclude_unset=True),
            source_ip=_source_ip(request),
        )
        result = _entity_response(session, record, keys)
        _set_etag(response, record.row_version)
    return result


@router.delete("/entities/{entity_id}", status_code=204)
def delete_entity(
    entity_id: UUID,
    request: Request,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, csrf, mutate=True)
        record = session.execute(
            select(Entity)
            .where(Entity.id == entity_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if record is None:
            acl.require_entity(
                session, actor.user_id, entity_id, acl.DELETE, source_ip=_source_ip(request)
            )
        record = acl.require_entity(
            session, actor.user_id, entity_id, acl.DELETE, source_ip=_source_ip(request)
        )
        if record.row_version != _if_match(if_match):
            raise DocVaultError("CONFLICT", detail="The entity changed. Reload and retry.")
        entities.soft_delete_entity(session, record, actor.user_id, source_ip=_source_ip(request))
    return Response(status_code=204)


@router.post("/entities/{entity_id}/restore", response_model=EntityResponse)
def restore_entity(
    entity_id: UUID,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> EntityResponse:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, csrf, mutate=True)
        session.execute(
            select(Entity)
            .where(Entity.id == entity_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        record = acl.require_entity(
            session,
            actor.user_id,
            entity_id,
            acl.DELETE,
            source_ip=_source_ip(request),
            include_deleted=True,
        )
        entities.restore_entity(session, record, actor.user_id, source_ip=_source_ip(request))
        result = _entity_response(session, record, keys)
        _set_etag(response, record.row_version)
    return result


@router.get("/entities/{entity_id}/identifiers", response_model=IdentifierListResponse)
def get_identifiers(
    entity_id: UUID,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> IdentifierListResponse:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, None, mutate=False)
        acl.require_entity(
            session, actor.user_id, entity_id, acl.VIEW, source_ip=_source_ip(request)
        )
        rows = entities.list_identifiers(session, entity_id)
        items = [
            IdentifierResponse.model_validate(entities.identifier_data(row, keys)) for row in rows
        ]
    return IdentifierListResponse(items=items)


@router.post(
    "/entities/{entity_id}/identifiers",
    response_model=IdentifierResponse,
    status_code=201,
)
def create_identifier(
    entity_id: UUID,
    body: IdentifierCreate,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> IdentifierResponse:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, csrf, mutate=True)
        acl.require_entity(
            session, actor.user_id, entity_id, acl.WRITE, source_ip=_source_ip(request)
        )
        row = entities.add_identifier(
            session,
            keys,
            entity_id=entity_id,
            actor_id=actor.user_id,
            id_type=body.id_type,
            value=body.value,
            label=body.label,
            duplicate_ack_of=body.duplicate_ack_of,
            source_ip=_source_ip(request),
        )
        _set_etag(response, row.row_version)
        return IdentifierResponse.model_validate(entities.identifier_data(row, keys))


@router.get("/identifiers/{identifier_id}/reveal", response_model=IdentifierResponse)
def reveal_identifier(
    identifier_id: UUID,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> IdentifierResponse:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, None, mutate=False)
        row = session.get(Identifier, identifier_id)
        if row is None or row.deleted_at is not None:
            raise DocVaultError("NOT_FOUND")
        acl.require_entity(
            session, actor.user_id, row.entity_id, acl.WRITE, source_ip=_source_ip(request)
        )
        return IdentifierResponse.model_validate(
            entities.reveal_identifier(
                session, keys, row, actor.user_id, source_ip=_source_ip(request)
            )
        )


@router.patch("/identifiers/{identifier_id}", response_model=IdentifierResponse)
def patch_identifier(
    identifier_id: UUID,
    body: IdentifierPatch,
    request: Request,
    response: Response,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> IdentifierResponse:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, csrf, mutate=True)
        row = session.get(Identifier, identifier_id)
        if row is None or row.deleted_at is not None:
            raise DocVaultError("NOT_FOUND")
        acl.require_entity(
            session, actor.user_id, row.entity_id, acl.WRITE, source_ip=_source_ip(request)
        )
        expected = _if_match(if_match)
        if row.row_version != expected:
            raise DocVaultError("CONFLICT", detail="The identifier changed. Reload and retry.")
        row = entities.patch_identifier(
            session,
            keys,
            identifier_id,
            actor.user_id,
            _if_match(if_match),
            body.model_dump(exclude_unset=True),
            source_ip=_source_ip(request),
        )
        _set_etag(response, row.row_version)
        result = IdentifierResponse.model_validate(entities.identifier_data(row, keys))
        _set_etag(response, row.row_version)
    return result


@router.delete("/identifiers/{identifier_id}", status_code=204)
def delete_identifier(
    identifier_id: UUID,
    request: Request,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, csrf, mutate=True)
        row = session.execute(
            select(Identifier)
            .where(Identifier.id == identifier_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if row is None or row.deleted_at is not None:
            raise DocVaultError("NOT_FOUND")
        acl.require_entity(
            session, actor.user_id, row.entity_id, acl.DELETE, source_ip=_source_ip(request)
        )
        if row.row_version != _if_match(if_match):
            raise DocVaultError("CONFLICT", detail="The identifier changed. Reload and retry.")
        row.deleted_at = datetime.now(UTC)
        row.row_version += 1
        append_event(
            session,
            action="identifier.delete",
            object_type="identifier",
            object_id=row.id,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
        )
    return Response(status_code=204)


@router.get("/entities/{entity_id}/persons", response_model=PersonListResponse)
def get_persons(
    entity_id: UUID,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> PersonListResponse:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, None, mutate=False)
        acl.require_entity(
            session, actor.user_id, entity_id, acl.VIEW, source_ip=_source_ip(request)
        )
        items = [
            PersonResponse.model_validate(row)
            for row in entities.list_persons(session, keys, entity_id)
        ]
    return PersonListResponse(items=items)


@router.post("/entities/{entity_id}/persons", response_model=PersonResponse, status_code=201)
def create_person(
    entity_id: UUID,
    body: PersonCreate,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> PersonResponse:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, csrf, mutate=True)
        entity = acl.require_entity(
            session, actor.user_id, entity_id, acl.WRITE, source_ip=_source_ip(request)
        )
        person = entities.add_person(
            session,
            keys,
            entity=entity,
            actor_id=actor.user_id,
            full_name=body.full_name,
            role=body.role,
            date_of_birth=body.date_of_birth,
            gender=body.gender,
            notes=body.notes,
            effective_from=body.effective_from,
            effective_to=body.effective_to,
            source_ip=_source_ip(request),
        )
        return PersonResponse(
            person_id=person.id,
            full_name=body.full_name.strip(),
            date_of_birth=person.date_of_birth,
            gender=person.gender,
            role=body.role,
            effective_from=body.effective_from,
            effective_to=body.effective_to,
        )


@router.delete(
    "/entities/{entity_id}/persons/{person_id}/{role}",
    status_code=204,
)
def delete_person(
    entity_id: UUID,
    person_id: UUID,
    role: PersonRole,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, csrf, mutate=True)
        entity = acl.require_entity(
            session, actor.user_id, entity_id, acl.WRITE, source_ip=_source_ip(request)
        )
        entities.remove_person(
            session, entity, person_id, role, actor.user_id, source_ip=_source_ip(request)
        )
    return Response(status_code=204)


@router.get("/entities/{entity_id}/documents")
def get_entity_documents(
    entity_id: UUID,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> dict[str, list[dict[str, object]]]:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, None, mutate=False)
        acl.require_entity(
            session, actor.user_id, entity_id, acl.VIEW, source_ip=_source_ip(request)
        )
        visible_ids = acl.visible_documents(session, actor.user_id).with_only_columns(Document.id)
        rows = session.execute(
            select(Document.id, Document.title_enc, Document.status, Document.row_version)
            .join(DocumentEntityLink, DocumentEntityLink.document_id == Document.id)
            .where(
                DocumentEntityLink.entity_id == entity_id,
                Document.id.in_(visible_ids),
            )
            .order_by(Document.created_at.desc(), Document.id.desc())
            .limit(100)
        )
        items: list[dict[str, object]] = [
            {
                "id": row.id,
                "title": decrypt_column(keys.meta_key, "documents", "title_enc", row.title_enc),
                "status": row.status,
                "row_version": row.row_version,
            }
            for row in rows
        ]
    return {"items": items}


@router.get("/entities/{entity_id}/timeline")
def get_entity_timeline(
    entity_id: UUID,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> dict[str, list[dict[str, object]]]:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, None, mutate=False)
        acl.require_entity(
            session, actor.user_id, entity_id, acl.VIEW, source_ip=_source_ip(request)
        )
        rows = entities.entity_timeline(session, entity_id, limit=limit)
        items: list[dict[str, object]] = [
            {
                "sequence": row.seq,
                "timestamp": row.ts,
                "action": row.action,
                "actor_id": row.actor_id,
                "outcome": row.outcome,
            }
            for row in rows
        ]
    return {"items": items}
