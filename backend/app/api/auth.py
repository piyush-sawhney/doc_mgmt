"""Authentication and current-session endpoints."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Cookie, Header, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as OrmSession

from app.core.errors import DocVaultError
from app.crypto.keys import VaultKeys
from app.services import acl, auth
from app.services.audit import append_event
from app.vault.session import VaultManager

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
COOKIE_NAME = "dv_session"


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class TotpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=6, max_length=6)


class PasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


class TotpDisableRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=1, max_length=1024)
    code: str | None = Field(default=None, min_length=6, max_length=6)


class UserSummary(BaseModel):
    id: UUID
    username: str
    display_name: str
    roles: tuple[str, ...]
    must_change_password: bool


class LoginResponse(BaseModel):
    totp_required: bool
    csrf_token: str
    user: UserSummary | None = None


class SessionResponse(BaseModel):
    user: UserSummary
    csrf_token: str
    capabilities: tuple[str, ...]


class TotpEnrollmentResponse(BaseModel):
    provisioning_uri: str
    secret: str


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


def _user_summary(session: auth.AuthenticatedSession) -> UserSummary:
    return UserSummary(
        id=session.user_id,
        username=session.username,
        display_name=session.display_name,
        roles=session.roles,
        must_change_password=session.must_change_password,
    )


def _authenticate(
    connection: OrmSession,
    keys: VaultKeys,
    token: str | None,
    csrf: str | None,
    *,
    allow_pending_totp: bool = False,
    allow_must_change_password: bool = False,
) -> auth.AuthenticatedSession:
    current = auth.authenticate(
        connection,
        keys,
        token,
        allow_pending_totp=allow_pending_totp,
        allow_must_change_password=allow_must_change_password,
    )
    auth.verify_csrf(connection, token, csrf)
    return current


def _set_cookie(response: Response, token: str, *, pending_totp: bool) -> None:
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=300 if pending_totp else 12 * 60 * 60,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )


@router.post("/login", response_model=LoginResponse)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
) -> LoginResponse:
    """Verify credentials and establish an active or TOTP-pending session."""
    result = auth.login(
        _engine(request),
        _keys(request),
        username=body.username,
        password=body.password,
        source_ip=_source_ip(request),
        user_agent=request.headers.get("user-agent", "")[:256],
    )
    _set_cookie(response, result.token, pending_totp=result.totp_required)
    return LoginResponse(
        totp_required=result.totp_required,
        csrf_token=result.session.csrf_token,
        user=None if result.totp_required else _user_summary(result.session),
    )


@router.post("/totp/verify", response_model=SessionResponse)
def verify_totp(
    body: TotpRequest,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> SessionResponse:
    """Complete a pending second-factor challenge."""
    keys = _keys(request)
    failure: DocVaultError | None = None
    activated: auth.AuthenticatedSession | None = None
    capabilities: tuple[str, ...] = ()
    with OrmSession(_engine(request)) as connection, connection.begin():
        current = _authenticate(
            connection,
            keys,
            token,
            csrf,
            allow_pending_totp=True,
            allow_must_change_password=True,
        )
        if not current.totp_pending:
            raise DocVaultError("AUTH_INVALID", detail="No TOTP challenge is pending.")
        try:
            activated = auth.pending_session_for_totp(
                connection, keys, current.session_id, body.code
            )
            capabilities = acl.capability_names(connection, activated.user_id)
        except DocVaultError as exc:
            if exc.code != "AUTH_INVALID":
                raise
            failure = exc
    if failure is not None:
        raise failure
    if activated is None:  # pragma: no cover - every non-error path promotes the session
        raise DocVaultError("INTERNAL_ERROR")
    if token is None:  # _authenticate already rejects this; narrows the type.
        raise DocVaultError("AUTH_REQUIRED")
    _set_cookie(response, token, pending_totp=False)
    return SessionResponse(
        user=_user_summary(activated),
        csrf_token=activated.csrf_token,
        capabilities=capabilities,
    )


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    """Revoke the current session."""
    keys = _keys(request)
    source_ip = _source_ip(request)
    with OrmSession(_engine(request)) as connection, connection.begin():
        current = _authenticate(
            connection,
            keys,
            token,
            csrf,
            allow_must_change_password=True,
        )
        auth.revoke_session(connection, current.session_id)
        append_event(
            connection,
            action="auth.logout",
            object_type="user",
            object_id=current.user_id,
            actor_id=current.user_id,
            source_ip=source_ip,
        )
    response.delete_cookie(COOKIE_NAME, path="/", secure=True, httponly=True, samesite="strict")
    response.status_code = 204
    return response


@router.get("/session", response_model=SessionResponse)
def current_session(
    request: Request,
    token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
) -> SessionResponse:
    """Return the authenticated user and current CSRF token."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as connection, connection.begin():
        current = auth.authenticate(
            connection,
            keys,
            token,
            allow_must_change_password=True,
        )
        capabilities = acl.capability_names(connection, current.user_id)
    return SessionResponse(
        user=_user_summary(current),
        csrf_token=current.csrf_token,
        capabilities=capabilities,
    )


@router.post("/password", status_code=204)
def change_password(
    body: PasswordRequest,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    """Change the account password and revoke all other sessions."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as connection, connection.begin():
        current = _authenticate(
            connection,
            keys,
            token,
            csrf,
            allow_must_change_password=True,
        )
        auth.change_password(
            connection,
            current.session_id,
            body.current_password,
            body.new_password,
            _source_ip(request),
        )
    response.status_code = 204
    return response


@router.post("/totp/enroll", response_model=TotpEnrollmentResponse)
def enroll_totp(
    request: Request,
    token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> TotpEnrollmentResponse:
    """Create and return a one-time TOTP enrollment secret."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as connection, connection.begin():
        current = _authenticate(connection, keys, token, csrf)
        uri, secret = auth.start_totp_enrollment(
            connection,
            keys,
            current.session_id,
            current.username,
        )
    return TotpEnrollmentResponse(provisioning_uri=uri, secret=secret)


@router.post("/totp/confirm", status_code=204)
def confirm_totp(
    body: TotpRequest,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    """Enable TOTP after a valid confirmation code."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as connection, connection.begin():
        current = _authenticate(connection, keys, token, csrf)
        auth.confirm_totp(connection, keys, current.session_id, body.code)
    response.status_code = 204
    return response


@router.post("/totp/disable", status_code=204)
def disable_totp(
    body: TotpDisableRequest,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    """Disable TOTP after confirming the password and current TOTP code."""
    keys = _keys(request)
    with OrmSession(_engine(request)) as connection, connection.begin():
        current = _authenticate(connection, keys, token, csrf)
        auth.disable_totp(
            connection,
            keys,
            current.session_id,
            body.password,
            body.code,
        )
    response.status_code = 204
    return response
