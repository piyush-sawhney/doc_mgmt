from __future__ import annotations

import base64
import time
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db import migrate
from app.db.enums import RoleName
from app.db.models.identity import User
from app.db.models.operations import AuditEvent
from app.main import create_app
from app.services.auth import _totp_code, create_user
from app.vault.init import InitResult
from app.vault.session import VaultManager

from .conftest import Pair

PASSWORD = "correct horse battery staple"
USERNAME = f"auth-{uuid.uuid4().hex[:8]}"


@pytest_asyncio.fixture
async def auth_client(
    pair: Pair,
    vault: tuple[Path, str, InitResult],
    settings: Settings,
) -> AsyncIterator[tuple[httpx.AsyncClient, uuid.UUID, str]]:
    migrate.upgrade(pair.dsn)
    engine = create_engine(pair.dsn)
    root, passphrase, _ = vault
    manager = VaultManager(root, app_version="0.1.0-test")
    manager.open()
    manager.unlock(passphrase)
    with Session(engine) as session, session.begin():
        user = create_user(
            session,
            manager.keys,
            username=USERNAME,
            display_name="Test Operator",
            password=PASSWORD,
            roles=(RoleName.ADMIN,),
            actor_id=None,
            source_ip="127.0.0.1",
            must_change_password=False,
        )
        user_id = user.id
    app = create_app(settings, vault=manager, db_engine=engine)
    app.state.vault = manager
    app.state.db_engine = engine
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 43123))
    client = httpx.AsyncClient(transport=transport, base_url="https://testserver")
    try:
        yield client, user_id, pair.dsn
    finally:
        await client.aclose()
        manager.close()
        engine.dispose()


async def _login(client: httpx.AsyncClient) -> tuple[str, str]:
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    assert response.status_code == 200
    data = response.json()
    return data["csrf_token"], client.cookies["dv_session"]


@pytest.mark.asyncio
async def test_login_session_csrf_logout_and_audit(
    auth_client: tuple[httpx.AsyncClient, uuid.UUID, str],
) -> None:
    client, user_id, dsn = auth_client
    assert (await client.get("/api/v1/auth/session")).status_code == 401

    csrf, _token = await _login(client)
    cookie = client.cookies.get("dv_session")
    assert cookie is not None
    cookie_metadata = next(item for item in client.cookies.jar if item.name == "dv_session")
    assert cookie_metadata.secure is True
    assert cookie_metadata.has_nonstandard_attr("HttpOnly")
    assert cookie_metadata.get_nonstandard_attr("SameSite") == "strict"

    current = await client.get("/api/v1/auth/session")
    assert current.status_code == 200
    assert current.json()["user"]["id"] == str(user_id)
    assert current.json()["csrf_token"] == csrf
    assert set(current.json()["capabilities"]) == {
        "view",
        "read",
        "write",
        "delete",
        "manage_acl",
        "print",
    }

    rejected = await client.post("/api/v1/auth/logout")
    assert rejected.status_code == 403
    assert rejected.json()["code"] == "CSRF_INVALID"

    logged_out = await client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
    assert logged_out.status_code == 204
    assert (await client.get("/api/v1/auth/session")).status_code == 401

    engine = create_engine(dsn)
    try:
        with Session(engine) as session:
            actions = list(
                session.execute(
                    select(AuditEvent.action).where(AuditEvent.actor_id == user_id)
                ).scalars()
            )
            assert "auth.login.allow" in actions
            assert "auth.logout" in actions
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_bad_password_is_audited_and_does_not_increment_unknown_user(
    auth_client: tuple[httpx.AsyncClient, uuid.UUID, str],
) -> None:
    client, user_id, dsn = auth_client
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": USERNAME, "password": "wrong password"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "AUTH_INVALID"

    engine = create_engine(dsn)
    try:
        with Session(engine) as session:
            user = session.get(User, user_id)
            assert user is not None
            assert user.failed_attempts == 1
            assert (
                session.execute(
                    select(AuditEvent.action).where(
                        AuditEvent.action == "auth.login.deny",
                        AuditEvent.actor_id == user_id,
                    )
                ).scalar_one()
                == "auth.login.deny"
            )
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_totp_enrollment_and_login_challenge(
    auth_client: tuple[httpx.AsyncClient, uuid.UUID, str],
) -> None:
    client, _user_id, _dsn = auth_client
    csrf, _token = await _login(client)
    headers = {"X-CSRF-Token": csrf}

    enrollment = await client.post("/api/v1/auth/totp/enroll", headers=headers)
    assert enrollment.status_code == 200
    secret_text = enrollment.json()["secret"]
    secret = base64.b32decode(secret_text + "=" * (-len(secret_text) % 8))
    confirmation_code = _totp_code(secret, int(time.time()))
    confirmed = await client.post(
        "/api/v1/auth/totp/confirm",
        json={"code": confirmation_code},
        headers=headers,
    )
    assert confirmed.status_code == 204

    await client.post("/api/v1/auth/logout", headers=headers)
    challenge = await client.post(
        "/api/v1/auth/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    assert challenge.status_code == 200
    assert challenge.json()["totp_required"] is True
    assert challenge.json()["user"] is None

    code = _totp_code(secret, int(time.time()))
    completed = await client.post(
        "/api/v1/auth/totp/verify",
        json={"code": code},
        headers={"X-CSRF-Token": challenge.json()["csrf_token"]},
    )
    assert completed.status_code == 200
    assert completed.json()["user"]["username"] == USERNAME
    assert (await client.get("/api/v1/auth/session")).status_code == 200
