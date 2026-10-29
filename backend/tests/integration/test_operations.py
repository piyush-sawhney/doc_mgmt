"""Auditor and administrator views of the audit trail and vault status."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db import migrate
from app.db.enums import RoleName
from app.main import create_app
from app.services.auth import create_user
from app.vault.init import InitResult
from app.vault.session import VaultManager

from .conftest import Pair

PASSWORD = "correct horse battery staple"


@pytest_asyncio.fixture
async def operations_api(
    pair: Pair,
    vault: tuple[Path, str, InitResult],
    settings: Settings,
) -> AsyncIterator[tuple[httpx.AsyncClient, dict[str, str]]]:
    migrate.upgrade(pair.dsn)
    engine = create_engine(pair.dsn)
    root, passphrase, _ = vault
    manager = VaultManager(root, app_version="0.1.0-test")
    manager.open()
    manager.unlock(passphrase)
    accounts = {
        "admin": (f"admin-{uuid.uuid4().hex[:8]}", RoleName.ADMIN),
        "auditor": (f"auditor-{uuid.uuid4().hex[:8]}", RoleName.AUDITOR),
        "reader": (f"reader-{uuid.uuid4().hex[:8]}", RoleName.READER),
    }
    with Session(engine) as session, session.begin():
        for username, role in accounts.values():
            create_user(
                session,
                manager.keys,
                username=username,
                display_name=username,
                password=PASSWORD,
                roles=(role,),
                actor_id=None,
                source_ip="127.0.0.1",
                must_change_password=False,
            )
    app = create_app(settings, vault=manager, db_engine=engine)
    app.state.vault = manager
    app.state.db_engine = engine
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 43124))
    client = httpx.AsyncClient(transport=transport, base_url="https://testserver")
    try:
        yield client, {name: username for name, (username, _role) in accounts.items()}
    finally:
        await client.aclose()
        manager.close()
        engine.dispose()


async def _login(client: httpx.AsyncClient, username: str) -> str:
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": PASSWORD},
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


@pytest.mark.asyncio
async def test_an_admin_can_list_and_filter_audit_events(
    operations_api: tuple[httpx.AsyncClient, dict[str, str]],
) -> None:
    client, users = operations_api
    await _login(client, users["admin"])

    response = await client.get("/api/v1/audit", params={"limit": 100})

    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 3
    assert {item["action"] for item in body["items"]} >= {"user.create"}
    created = await client.get("/api/v1/audit", params={"action": "user.create"})
    assert created.status_code == 200
    assert all(item["action"] == "user.create" for item in created.json()["items"])
    assert created.json()["total"] == 3


@pytest.mark.asyncio
async def test_an_auditor_reads_the_index_but_a_reader_cannot(
    operations_api: tuple[httpx.AsyncClient, dict[str, str]],
) -> None:
    client, users = operations_api
    await _login(client, users["auditor"])
    assert (await client.get("/api/v1/audit")).status_code == 200

    await _login(client, users["reader"])
    denied = await client.get("/api/v1/audit")
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_verifying_the_chain_reports_a_tampered_file(
    operations_api: tuple[httpx.AsyncClient, dict[str, str]],
    vault: tuple[Path, str, InitResult],
) -> None:
    client, users = operations_api
    csrf = await _login(client, users["admin"])
    healthy = await client.post("/api/v1/audit/verify", headers={"X-CSRF-Token": csrf})
    assert healthy.status_code == 200
    assert healthy.json()["ok"] is True
    assert healthy.json()["entries"] >= 2

    root, _passphrase, _result = vault
    first = sorted((root / "audit").glob("*.jsonl"))[0]
    lines = first.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"outcome":"allow"', '"outcome":"deny"')
    first.write_text("\n".join(lines) + "\n", encoding="utf-8")

    broken = await client.post("/api/v1/audit/verify", headers={"X-CSRF-Token": csrf})
    assert broken.status_code == 200
    assert broken.json()["ok"] is False
    assert broken.json()["first_bad_seq"] == 1


@pytest.mark.asyncio
async def test_a_bare_post_to_verify_is_refused_without_csrf(
    operations_api: tuple[httpx.AsyncClient, dict[str, str]],
) -> None:
    client, users = operations_api
    await _login(client, users["admin"])

    response = await client.post("/api/v1/audit/verify")

    assert response.status_code == 403
    assert response.json()["code"] == "CSRF_INVALID"


@pytest.mark.asyncio
async def test_vault_status_reports_public_facts_without_key_material(
    operations_api: tuple[httpx.AsyncClient, dict[str, str]],
) -> None:
    client, users = operations_api
    await _login(client, users["admin"])

    response = await client.get("/api/v1/vault/status")

    assert response.status_code == 200
    body = response.json()
    assert body["blob_count"] == 0
    assert body["size_bytes"] > 0
    assert body["lock_state"] == "held"
    assert body["postgres_version"]
    assert len(body["key_fingerprint"]) == 32
    assert "keys" not in response.text
    assert "kek" not in response.text


@pytest.mark.asyncio
async def test_only_an_admin_reads_vault_status(
    operations_api: tuple[httpx.AsyncClient, dict[str, str]],
) -> None:
    client, users = operations_api
    await _login(client, users["auditor"])

    assert (await client.get("/api/v1/vault/status")).status_code == 403
