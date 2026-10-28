"""Health endpoints, request correlation, and RFC 9457 errors.

These tests talk to the ASGI app through ``httpx.ASGITransport`` with the real
lifespan. ``fastapi.testclient`` is avoided on purpose: the pinned Starlette
deprecates it in favour of ``httpx2``, and ``httpx`` is what the project pins.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest

from app.core.config import Settings
from app.core.errors import DocVaultError
from app.main import create_app
from app.vault.session import VaultManager


@asynccontextmanager
async def _client(
    settings: Settings, root: Path
) -> AsyncIterator[tuple[httpx.AsyncClient, VaultManager]]:
    manager = VaultManager(root, app_version="test")
    app = create_app(settings=settings, vault=manager, app_version="test")

    @app.get("/boom")
    async def boom() -> None:
        raise DocVaultError("NOT_FOUND", detail="Nothing here.")

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client, manager


@pytest.mark.asyncio
async def test_healthz_is_alive_without_unlocking(
    settings: Settings, vault: tuple[Path, str, object]
) -> None:
    # Arrange
    root, _passphrase, _result = vault

    # Act
    async with _client(settings, root) as (client, _manager):
        response = await client.get("/healthz")

    # Assert
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_readyz_reports_a_locked_vault_as_a_problem(
    settings: Settings, vault: tuple[Path, str, object]
) -> None:
    # Arrange
    root, _passphrase, _result = vault

    # Act
    async with _client(settings, root) as (client, _manager):
        response = await client.get("/readyz")

    # Assert
    assert response.status_code == 503
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "VAULT_LOCKED"


@pytest.mark.asyncio
async def test_readyz_is_ready_after_unlock(
    settings: Settings, vault: tuple[Path, str, object]
) -> None:
    # Arrange
    root, passphrase, _result = vault

    # Act
    async with _client(settings, root) as (client, manager):
        manager.unlock(passphrase)
        response = await client.get("/readyz")

    # Assert
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"vault": "unlocked"}}


@pytest.mark.asyncio
async def test_problem_documents_echo_the_request_id(
    settings: Settings, vault: tuple[Path, str, object]
) -> None:
    # Arrange
    root, _passphrase, _result = vault

    # Act
    async with _client(settings, root) as (client, _manager):
        response = await client.get("/boom", headers={"X-Request-Id": "TEST-REQUEST-1"})

    # Assert
    assert response.status_code == 404
    assert response.headers["X-Request-Id"] == "TEST-REQUEST-1"
    assert response.json()["request_id"] == "TEST-REQUEST-1"
    assert response.json()["title"] == "Not found"


@pytest.mark.asyncio
async def test_unknown_route_is_a_problem_document(
    settings: Settings, vault: tuple[Path, str, object]
) -> None:
    # Arrange
    root, _passphrase, _result = vault

    # Act
    async with _client(settings, root) as (client, _manager):
        response = await client.get("/does-not-exist")

    # Assert
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "NOT_FOUND"
