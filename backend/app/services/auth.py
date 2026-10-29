"""Authentication, session, password, and TOTP operations."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
import struct
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final
from urllib.parse import quote

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import select, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.core.errors import DocVaultError
from app.core.time import now_utc
from app.crypto.canonical import b64url_encode
from app.crypto.keys import VaultKeys, decrypt_column, encrypt_column
from app.db.enums import RoleName, SessionState, UserStatus
from app.db.models.identity import Session as DbSession
from app.db.models.identity import User, UserRole
from app.services.audit import append_event

USERNAME_RE: Final = re.compile(r"^[a-z0-9._-]{3,64}$")
SESSION_IDLE: Final = timedelta(minutes=30)
SESSION_ABSOLUTE: Final = timedelta(hours=12)
PENDING_TOTP_TTL: Final = timedelta(minutes=5)
RATE_WINDOW_SECONDS: Final = 300.0
RATE_USERNAME_LIMIT: Final = 5
RATE_IP_LIMIT: Final = 20

_hasher = PasswordHasher()
_dummy_hash = _hasher.hash(secrets.token_urlsafe(32))


def normalize_username(username: str) -> str:
    """Validate and canonicalize a login name."""
    normalized = username.strip().lower()
    if not USERNAME_RE.fullmatch(normalized):
        raise DocVaultError(
            "VALIDATION_FAILED",
            fields=[{"field": "username", "code": "format", "message": "Invalid username."}],
        )
    return normalized


def username_blind_index(bidx_key: bytes, username: str) -> bytes:
    """Create the versioned equality index without discarding username punctuation."""
    normalized = normalize_username(username)
    digest = hmac.new(
        bidx_key,
        f"v1|username|{normalized}".encode("ascii"),
        hashlib.sha256,
    ).digest()
    return b"\x01" + digest


def hash_password(password: str) -> str:
    """Hash a password with the configured Argon2id parameters."""
    validate_password(password)
    return _hasher.hash(password)


def validate_password(password: str) -> None:
    """Enforce the baseline password length policy."""
    if len(password) < 12:
        raise DocVaultError(
            "PASSWORD_POLICY",
            fields=[{"field": "password", "code": "too_short", "message": "Minimum length is 12."}],
        )


def _password_matches(encoded: str, password: str) -> bool:
    try:
        return _hasher.verify(encoded, password)
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        return False


@dataclass(frozen=True, slots=True)
class AuthenticatedSession:
    """Safe session facts returned by authentication."""

    session_id: uuid.UUID
    user_id: uuid.UUID
    username: str
    display_name: str
    roles: tuple[str, ...]
    csrf_token: str
    must_change_password: bool
    totp_pending: bool = False


@dataclass(frozen=True, slots=True)
class LoginResult:
    """Login response plus the opaque cookie value."""

    session: AuthenticatedSession
    token: str
    totp_required: bool


class LoginThrottle:
    """Process-local failed-login limiter for username and source IP."""

    def __init__(self) -> None:
        self._attempts: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, username: str, source_ip: str, *, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        with self._lock:
            for kind, value, limit in (
                ("username", username, RATE_USERNAME_LIMIT),
                ("ip", source_ip, RATE_IP_LIMIT),
            ):
                attempts = self._attempts[(kind, value)]
                while attempts and current - attempts[0] >= RATE_WINDOW_SECONDS:
                    attempts.popleft()
                if len(attempts) >= limit:
                    retry = max(1, int(RATE_WINDOW_SECONDS - (current - attempts[0])))
                    raise DocVaultError(
                        "RATE_LIMITED",
                        detail=f"Too many login attempts. Retry in {retry} seconds.",
                        retry_after=retry,
                    )

    def failed(self, username: str, source_ip: str, *, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        with self._lock:
            self._attempts[("username", username)].append(current)
            self._attempts[("ip", source_ip)].append(current)

    def succeeded(self, username: str, source_ip: str) -> None:
        with self._lock:
            self._attempts.pop(("username", username), None)
            self._attempts.pop(("ip", source_ip), None)


login_throttle = LoginThrottle()


def _user_summary(
    connection: Session,
    user: User,
    keys: VaultKeys,
    session: DbSession,
    *,
    totp_pending: bool = False,
) -> AuthenticatedSession:
    roles = tuple(
        sorted(
            row.role.value
            for row in connection.execute(
                select(UserRole).where(UserRole.user_id == user.id)
            ).scalars()
        )
    )
    username = decrypt_column(keys.meta_key, "users", "username_enc", user.username_enc)
    display_name = decrypt_column(keys.meta_key, "users", "display_name_enc", user.display_name_enc)
    if username is None or display_name is None:
        raise DocVaultError("COLUMN_TAMPERED", detail="Required user identity is null.")
    return AuthenticatedSession(
        session_id=session.id,
        user_id=user.id,
        username=username,
        display_name=display_name,
        roles=roles,
        csrf_token=b64url_encode(session.csrf_secret),
        must_change_password=user.must_change_password,
        totp_pending=totp_pending,
    )


def create_user(
    connection: Session,
    keys: VaultKeys,
    *,
    username: str,
    display_name: str,
    password: str,
    roles: tuple[RoleName, ...],
    actor_id: uuid.UUID | None,
    source_ip: str | None,
    must_change_password: bool = True,
) -> User:
    """Create an encrypted account and its initial roles atomically."""
    normalized = normalize_username(username)
    blind = username_blind_index(keys.bidx_key, normalized)
    existing = connection.execute(
        select(User.id).where(User.username_blind == blind)
    ).scalar_one_or_none()
    if existing is not None:
        raise DocVaultError("CONFLICT", detail="That username is already in use.")
    if not roles:
        raise DocVaultError(
            "VALIDATION_FAILED",
            fields=[
                {
                    "field": "roles",
                    "code": "empty",
                    "message": "At least one role is required.",
                }
            ],
        )
    user = User(
        username_enc=encrypt_column(keys.meta_key, "users", "username_enc", normalized),
        username_blind=blind,
        display_name_enc=encrypt_column(
            keys.meta_key, "users", "display_name_enc", display_name.strip()
        ),
        password_hash=hash_password(password),
        must_change_password=must_change_password,
        created_by=actor_id,
    )
    connection.add(user)
    connection.flush()
    for role in sorted(set(roles), key=lambda value: value.value):
        connection.add(UserRole(user_id=user.id, role=role))
    append_event(
        connection,
        action="user.create",
        object_type="user",
        object_id=user.id,
        actor_id=actor_id,
        source_ip=source_ip,
        detail={"roles": sorted(role.value for role in set(roles))},
    )
    return user


def _new_session(
    connection: Session,
    user: User,
    *,
    source_ip: str,
    user_agent: str,
    pending_totp: bool,
) -> tuple[DbSession, str]:
    now = now_utc()
    token = b64url_encode(secrets.token_bytes(32))
    ttl = PENDING_TOTP_TTL if pending_totp else SESSION_IDLE
    absolute = now + (PENDING_TOTP_TTL if pending_totp else SESSION_ABSOLUTE)
    session = DbSession(
        user_id=user.id,
        token_hash=hashlib.sha256(token.encode("ascii")).digest(),
        csrf_secret=secrets.token_bytes(32),
        state=SessionState.PENDING_TOTP if pending_totp else SessionState.ACTIVE,
        idle_expires_at=now + ttl,
        absolute_expires_at=absolute,
        source_ip=source_ip,
        user_agent=user_agent[:256],
    )
    connection.add(session)
    connection.flush()
    return session, token


def login(
    engine: Engine,
    keys: VaultKeys,
    *,
    username: str,
    password: str,
    source_ip: str,
    user_agent: str,
) -> LoginResult:
    """Authenticate and create an active or TOTP-pending session."""
    normalized = normalize_username(username)
    login_throttle.check(normalized, source_ip)
    blind = username_blind_index(keys.bidx_key, normalized)
    denied = False
    result: LoginResult | None = None
    with Session(engine) as connection, connection.begin():
        user = connection.execute(
            select(User).where(User.username_blind == blind).with_for_update()
        ).scalar_one_or_none()
        encoded = user.password_hash if user is not None else _dummy_hash
        valid = _password_matches(encoded, password)
        if user is None or not valid or user.status is not UserStatus.ACTIVE:
            login_throttle.failed(normalized, source_ip)
            if user is not None:
                user.failed_attempts = min(user.failed_attempts + 1, 32767)
            append_event(
                connection,
                action="auth.login.deny",
                object_type="user",
                object_id=user.id if user is not None else None,
                actor_id=user.id if user is not None else None,
                outcome="deny",
                source_ip=source_ip,
                detail={"reason": "invalid_credentials"},
            )
            denied = True
        else:
            login_throttle.succeeded(normalized, source_ip)
            user.failed_attempts = 0
            user.last_login_at = now_utc()
            session, token = _new_session(
                connection,
                user,
                source_ip=source_ip,
                user_agent=user_agent,
                pending_totp=user.totp_enabled,
            )
            append_event(
                connection,
                action="auth.login.challenge" if user.totp_enabled else "auth.login.allow",
                object_type="user",
                object_id=user.id,
                actor_id=user.id,
                source_ip=source_ip,
                detail={"totp_required": user.totp_enabled},
            )
            summary = _user_summary(
                connection,
                user,
                keys,
                session,
                totp_pending=user.totp_enabled,
            )
            result = LoginResult(
                session=summary,
                token=token,
                totp_required=user.totp_enabled,
            )
    if denied:
        raise DocVaultError("AUTH_INVALID")
    if result is None:  # pragma: no cover - every transaction path assigns one result
        raise DocVaultError("INTERNAL_ERROR")
    return result


def authenticate(
    connection: Session,
    keys: VaultKeys,
    token: str | None,
    *,
    allow_pending_totp: bool = False,
    allow_must_change_password: bool = False,
) -> AuthenticatedSession:
    """Resolve and touch a live session from its opaque cookie."""
    if not token:
        raise DocVaultError("AUTH_REQUIRED")
    token_hash = hashlib.sha256(token.encode("ascii", "ignore")).digest()
    session = connection.execute(
        select(DbSession)
        .where(DbSession.token_hash == token_hash, DbSession.revoked_at.is_(None))
        .with_for_update()
    ).scalar_one_or_none()
    now = now_utc()
    if (
        session is None
        or session.idle_expires_at <= now
        or session.absolute_expires_at <= now
        or (session.state is SessionState.PENDING_TOTP and not allow_pending_totp)
    ):
        raise DocVaultError("SESSION_EXPIRED")
    user = connection.get(User, session.user_id)
    if user is None or user.status is not UserStatus.ACTIVE:
        raise DocVaultError("SESSION_EXPIRED")
    if user.must_change_password and not allow_must_change_password:
        raise DocVaultError("PASSWORD_CHANGE_REQUIRED")
    session.last_seen_at = now
    session.idle_expires_at = min(now + SESSION_IDLE, session.absolute_expires_at)
    return _user_summary(
        connection,
        user,
        keys,
        session,
        totp_pending=session.state is SessionState.PENDING_TOTP,
    )


def verify_csrf(connection: Session, token: str | None, csrf: str | None) -> None:
    """Constant-time compare the CSRF request header with the current session."""
    if not token or not csrf:
        raise DocVaultError("CSRF_INVALID")
    session_hash = hashlib.sha256(token.encode("ascii", "ignore")).digest()
    session = connection.execute(
        select(DbSession).where(
            DbSession.token_hash == session_hash,
            DbSession.revoked_at.is_(None),
        )
    ).scalar_one_or_none()
    if session is None or not hmac.compare_digest(b64url_encode(session.csrf_secret), csrf):
        raise DocVaultError("CSRF_INVALID")


def revoke_session(
    connection: Session,
    session_id: uuid.UUID,
    *,
    at: datetime | None = None,
) -> None:
    """Revoke one session."""
    connection.execute(
        update(DbSession)
        .where(DbSession.id == session_id, DbSession.revoked_at.is_(None))
        .values(revoked_at=at or now_utc())
    )


def _totp_code(secret: bytes, moment: int) -> str:
    counter = moment // 30
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def verify_totp(secret: bytes, code: str, *, moment: int | None = None) -> bool:
    """Validate a six-digit TOTP code with a one-step clock-skew window."""
    if not re.fullmatch(r"\d{6}", code):
        return False
    timestamp = int(time.time()) if moment is None else moment
    return any(
        hmac.compare_digest(_totp_code(secret, timestamp + shift * 30), code)
        for shift in (-1, 0, 1)
    )


def new_totp_secret() -> bytes:
    """Generate an RFC 6238 160-bit shared secret."""
    return secrets.token_bytes(20)


def totp_uri(username: str, secret: bytes) -> tuple[str, str]:
    """Return one provisioning URI and base32 secret for authenticator apps."""
    encoded = base64.b32encode(secret).decode("ascii").rstrip("=")
    label = quote(f"DocVault:{username}")
    uri = f"otpauth://totp/{label}?secret={encoded}&issuer=DocVault&digits=6&period=30"
    return uri, encoded


def pending_session_for_totp(
    connection: Session,
    keys: VaultKeys,
    session_id: uuid.UUID,
    code: str,
) -> AuthenticatedSession:
    """Promote a pending session after validating the account's TOTP."""
    session = connection.execute(
        select(DbSession).where(DbSession.id == session_id).with_for_update()
    ).scalar_one_or_none()
    now = now_utc()
    if (
        session is None
        or session.state is not SessionState.PENDING_TOTP
        or session.revoked_at is not None
        or session.idle_expires_at <= now
        or session.absolute_expires_at <= now
    ):
        raise DocVaultError("SESSION_EXPIRED")
    user = connection.get(User, session.user_id)
    if user is None or user.totp_secret_enc is None or not user.totp_enabled:
        raise DocVaultError("AUTH_INVALID")
    secret_text = decrypt_column(keys.meta_key, "users", "totp_secret_enc", user.totp_secret_enc)
    if secret_text is None:
        raise DocVaultError("COLUMN_TAMPERED", detail="TOTP secret is missing.")
    try:
        secret = base64.b32decode(secret_text + "=" * (-len(secret_text) % 8))
    except (ValueError, binascii.Error) as exc:
        raise DocVaultError("COLUMN_TAMPERED", detail="TOTP secret is malformed.") from exc
    if not verify_totp(secret, code):
        append_event(
            connection,
            action="auth.totp.deny",
            object_type="user",
            object_id=user.id,
            actor_id=user.id,
            outcome="deny",
            source_ip=session.source_ip,
            detail={"reason": "invalid_code"},
        )
        raise DocVaultError("AUTH_INVALID")
    session.state = SessionState.ACTIVE
    session.idle_expires_at = min(now + SESSION_IDLE, session.absolute_expires_at)
    session.absolute_expires_at = now + SESSION_ABSOLUTE
    session.idle_expires_at = now + SESSION_IDLE
    append_event(
        connection,
        action="auth.totp.allow",
        object_type="user",
        object_id=user.id,
        actor_id=user.id,
        source_ip=session.source_ip,
    )
    return _user_summary(connection, user, keys, session)


def start_totp_enrollment(
    connection: Session,
    keys: VaultKeys,
    session_id: uuid.UUID,
    username: str,
) -> tuple[str, str]:
    """Replace the pending TOTP secret and return its provisioning data once."""
    session = connection.get(DbSession, session_id)
    if session is None:
        raise DocVaultError("SESSION_EXPIRED")
    user = connection.get(User, session.user_id)
    if user is None:
        raise DocVaultError("SESSION_EXPIRED")
    secret = new_totp_secret()
    encoded_secret = base64.b32encode(secret).decode("ascii")
    user.totp_secret_enc = encrypt_column(keys.meta_key, "users", "totp_secret_enc", encoded_secret)
    user.totp_enabled = False
    uri, secret_text = totp_uri(username, secret)
    append_event(
        connection,
        action="auth.totp.enroll",
        object_type="user",
        object_id=user.id,
        actor_id=user.id,
        source_ip=session.source_ip,
    )
    return uri, secret_text


def confirm_totp(
    connection: Session,
    keys: VaultKeys,
    session_id: uuid.UUID,
    code: str,
) -> None:
    """Enable TOTP only after proving control of the enrolled secret."""
    session = connection.get(DbSession, session_id)
    user = connection.get(User, session.user_id) if session is not None else None
    if user is None or user.totp_secret_enc is None:
        raise DocVaultError("AUTH_INVALID", detail="No TOTP enrollment is pending.")
    encoded = decrypt_column(keys.meta_key, "users", "totp_secret_enc", user.totp_secret_enc)
    if encoded is None:
        raise DocVaultError("COLUMN_TAMPERED", detail="TOTP secret is missing.")
    try:
        secret = base64.b32decode(encoded + "=" * (-len(encoded) % 8))
    except (ValueError, binascii.Error) as exc:
        raise DocVaultError("COLUMN_TAMPERED", detail="TOTP secret is malformed.") from exc
    if not verify_totp(secret, code):
        raise DocVaultError("AUTH_INVALID", detail="TOTP code is incorrect.")
    user.totp_enabled = True
    append_event(
        connection,
        action="auth.totp.confirm",
        object_type="user",
        object_id=user.id,
        actor_id=user.id,
        source_ip=session.source_ip if session is not None else None,
    )


def disable_totp(
    connection: Session,
    keys: VaultKeys,
    session_id: uuid.UUID,
    password: str,
    code: str | None,
) -> None:
    """Disable TOTP after password and, when enabled, current code verification."""
    session = connection.get(DbSession, session_id)
    if session is None:
        raise DocVaultError("SESSION_EXPIRED")
    user = connection.get(User, session.user_id)
    if user is None or not _password_matches(user.password_hash, password):
        raise DocVaultError("AUTH_INVALID")
    if user.totp_enabled:
        if code is None or user.totp_secret_enc is None:
            raise DocVaultError("AUTH_INVALID")
        encoded = decrypt_column(keys.meta_key, "users", "totp_secret_enc", user.totp_secret_enc)
        if encoded is None:
            raise DocVaultError("COLUMN_TAMPERED", detail="TOTP secret is missing.")
        try:
            secret = base64.b32decode(encoded + "=" * (-len(encoded) % 8))
        except (ValueError, binascii.Error) as exc:
            raise DocVaultError("COLUMN_TAMPERED", detail="TOTP secret is malformed.") from exc
        if not verify_totp(secret, code):
            raise DocVaultError("AUTH_INVALID")
    user.totp_enabled = False
    user.totp_secret_enc = None
    append_event(
        connection,
        action="auth.totp.disable",
        object_type="user",
        object_id=user.id,
        actor_id=user.id,
        source_ip=session.source_ip if session is not None else None,
    )


def change_password(
    connection: Session,
    session_id: uuid.UUID,
    current_password: str,
    new_password: str,
    source_ip: str | None,
) -> None:
    """Change one password and revoke every other session for the account."""
    session = connection.get(DbSession, session_id)
    if session is None:
        raise DocVaultError("SESSION_EXPIRED")
    user = connection.get(User, session.user_id)
    if user is None or not _password_matches(user.password_hash, current_password):
        raise DocVaultError("AUTH_INVALID")
    validate_password(new_password)
    if _password_matches(user.password_hash, new_password):
        raise DocVaultError(
            "PASSWORD_POLICY",
            detail="The new password must differ from the current password.",
        )
    now = now_utc()
    user.password_hash = _hasher.hash(new_password)
    user.password_changed_at = now
    user.must_change_password = False
    connection.execute(
        update(DbSession)
        .where(
            DbSession.user_id == user.id,
            DbSession.id != session.id,
            DbSession.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    append_event(
        connection,
        action="auth.password.change",
        object_type="user",
        object_id=user.id,
        actor_id=user.id,
        source_ip=source_ip,
    )


def session_roles(connection: Session, user_id: uuid.UUID) -> tuple[str, ...]:
    """Return current roles for a user."""
    return tuple(
        sorted(
            row.role.value
            for row in connection.execute(
                select(UserRole).where(UserRole.user_id == user_id)
            ).scalars()
        )
    )
