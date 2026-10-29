"""Administrator-only user and group management."""

from __future__ import annotations

import secrets
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Cookie, Header, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as OrmSession

from app.core.errors import DocVaultError
from app.crypto.keys import VaultKeys
from app.db.enums import RoleName, UserStatus
from app.services import admin, auth
from app.vault.session import VaultManager

router = APIRouter(prefix="/api/v1", tags=["administration"])


class UserCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=64)
    display_name: str = Field(min_length=1, max_length=200)
    roles: tuple[RoleName, ...] = Field(min_length=1)


class UserPatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    status: UserStatus | None = None
    roles: tuple[RoleName, ...] | None = Field(default=None, min_length=1)


class UserResponse(BaseModel):
    id: UUID
    username: str
    display_name: str
    status: UserStatus
    roles: tuple[RoleName, ...]
    must_change_password: bool


class UserCreatedResponse(UserResponse):
    temporary_password: str


class UserListResponse(BaseModel):
    items: list[UserResponse]


class ResetPasswordResponse(BaseModel):
    temporary_password: str
    must_change_password: bool = True


class SessionsRevokedResponse(BaseModel):
    revoked: int


class GroupCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)


class GroupPatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)


class GroupMembersRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_ids: tuple[UUID, ...]


class GroupResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    is_system: bool
    user_ids: tuple[UUID, ...]


class GroupListResponse(BaseModel):
    items: list[GroupResponse]


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


def _admin_actor(
    session: OrmSession,
    keys: VaultKeys,
    token: str | None,
    csrf: str | None,
    *,
    require_csrf: bool,
) -> auth.AuthenticatedSession:
    actor = auth.authenticate(session, keys, token)
    if require_csrf:
        auth.verify_csrf(session, token, csrf)
    if RoleName.ADMIN.value not in actor.roles:
        raise DocVaultError("FORBIDDEN", detail="Administrator role is required.")
    return actor


def _user_response(record: admin.UserRecord) -> UserResponse:
    return UserResponse(
        id=record.id,
        username=record.username,
        display_name=record.display_name,
        status=record.status,
        roles=record.roles,
        must_change_password=record.must_change_password,
    )


def _group_response(record: admin.GroupRecord) -> GroupResponse:
    return GroupResponse(
        id=record.id,
        name=record.name,
        description=record.description,
        is_system=record.is_system,
        user_ids=record.user_ids,
    )


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


@router.get("/users", response_model=UserListResponse)
def list_users(
    request: Request,
    status: UserStatus | None = None,
    role: RoleName | None = None,
    q: str | None = Query(default=None, max_length=128),
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> UserListResponse:
    """List users for administrators."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        _admin_actor(session, keys, token, None, require_csrf=False)
        records = admin.list_users(session, keys, status=status, role=role, query=q)
    return UserListResponse(items=[_user_response(record) for record in records])


@router.post("/users", response_model=UserCreatedResponse, status_code=201)
def create_user(
    body: UserCreateRequest,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> UserCreatedResponse:
    """Create an account with a one-time temporary password."""
    keys = _keys(request)
    temporary_password = secrets.token_urlsafe(18)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _admin_actor(session, keys, token, csrf, require_csrf=True)
        user = auth.create_user(
            session,
            keys,
            username=body.username,
            display_name=body.display_name,
            password=temporary_password,
            roles=body.roles,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
        )
        record = admin.get_user(session, keys, user.id)
    _set_etag(response, record.row_version)
    created = _user_response(record).model_dump()
    return UserCreatedResponse(**created, temporary_password=temporary_password)


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(
    user_id: UUID,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> UserResponse:
    """Read one user and its ETag."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        _admin_actor(session, keys, token, None, require_csrf=False)
        record = admin.get_user(session, keys, user_id)
    _set_etag(response, record.row_version)
    return _user_response(record)


@router.patch("/users/{user_id}", response_model=UserResponse)
def patch_user(
    user_id: UUID,
    body: UserPatchRequest,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> UserResponse:
    """Update an account with an optimistic-concurrency check."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _admin_actor(session, keys, token, csrf, require_csrf=True)
        record = admin.update_user(
            session,
            keys,
            user_id,
            expected_version=_if_match(if_match),
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
            display_name=body.display_name,
            status=body.status,
            roles=body.roles,
        )
    _set_etag(response, record.row_version)
    return _user_response(record)


@router.post("/users/{user_id}/reset-password", response_model=ResetPasswordResponse)
def reset_user_password(
    user_id: UUID,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> ResetPasswordResponse:
    """Reset an account password and return the temporary secret once."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _admin_actor(session, keys, token, csrf, require_csrf=True)
        temporary_password = admin.reset_password(
            session,
            user_id,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
        )
    return ResetPasswordResponse(temporary_password=temporary_password)


@router.post(
    "/users/{user_id}/sessions/revoke",
    response_model=SessionsRevokedResponse,
)
def revoke_sessions(
    user_id: UUID,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> SessionsRevokedResponse:
    """Revoke every live session for one account."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _admin_actor(session, keys, token, csrf, require_csrf=True)
        count = admin.revoke_user_sessions(
            session,
            user_id,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
        )
    return SessionsRevokedResponse(revoked=count)


@router.get("/groups", response_model=GroupListResponse)
def list_groups(
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> GroupListResponse:
    """List groups and members."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        _admin_actor(session, keys, token, None, require_csrf=False)
        records = admin.list_groups(session, keys)
    return GroupListResponse(items=[_group_response(record) for record in records])


@router.post("/groups", response_model=GroupResponse, status_code=201)
def create_group(
    body: GroupCreateRequest,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> GroupResponse:
    """Create a user-defined sharing group."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _admin_actor(session, keys, token, csrf, require_csrf=True)
        record = admin.create_group(
            session,
            keys,
            name=body.name,
            description=body.description,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
        )
    _set_etag(response, record.row_version)
    return _group_response(record)


@router.get("/groups/{group_id}", response_model=GroupResponse)
def get_group(
    group_id: UUID,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> GroupResponse:
    """Read one group and its ETag."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        _admin_actor(session, keys, token, None, require_csrf=False)
        record = admin.get_group(session, keys, group_id)
    _set_etag(response, record.row_version)
    return _group_response(record)


@router.patch("/groups/{group_id}", response_model=GroupResponse)
def patch_group(
    group_id: UUID,
    body: GroupPatchRequest,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> GroupResponse:
    """Update group metadata with an optimistic-concurrency check."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _admin_actor(session, keys, token, csrf, require_csrf=True)
        record = admin.update_group(
            session,
            keys,
            group_id,
            expected_version=_if_match(if_match),
            name=body.name,
            description=body.description,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
        )
    _set_etag(response, record.row_version)
    return _group_response(record)


@router.delete("/groups/{group_id}", status_code=204)
def delete_group(
    group_id: UUID,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> Response:
    """Delete a non-system group with an ETag check."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _admin_actor(session, keys, token, csrf, require_csrf=True)
        admin.delete_group(
            session,
            group_id,
            expected_version=_if_match(if_match),
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
        )
    response.status_code = 204
    return response


@router.put("/groups/{group_id}/members", response_model=GroupResponse)
def replace_members(
    group_id: UUID,
    body: GroupMembersRequest,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> GroupResponse:
    """Replace all group members atomically."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _admin_actor(session, keys, token, csrf, require_csrf=True)
        record = admin.replace_group_members(
            session,
            keys,
            group_id,
            body.user_ids,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
        )
    _set_etag(response, record.row_version)
    return _group_response(record)
