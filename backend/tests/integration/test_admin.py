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

ADMIN_USERNAME = f"admin-{uuid.uuid4().hex[:8]}"
ADMIN_PASSWORD = "correct horse battery staple"


@pytest_asyncio.fixture
async def admin_api(
    pair: Pair,
    vault: tuple[Path, str, InitResult],
    settings: Settings,
) -> AsyncIterator[httpx.AsyncClient]:
    migrate.upgrade(pair.dsn)
    engine = create_engine(pair.dsn)
    root, passphrase, _ = vault
    manager = VaultManager(root, app_version="0.1.0-test")
    manager.open()
    manager.unlock(passphrase)
    with Session(engine) as session, session.begin():
        create_user(
            session,
            manager.keys,
            username=ADMIN_USERNAME,
            display_name="Initial Admin",
            password=ADMIN_PASSWORD,
            roles=(RoleName.ADMIN,),
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
        yield client
    finally:
        await client.aclose()
        manager.close()
        engine.dispose()


async def _login_admin(client: httpx.AsyncClient) -> str:
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


@pytest.mark.asyncio
async def test_user_admin_etags_reset_and_last_admin_guard(admin_api: httpx.AsyncClient) -> None:
    csrf = await _login_admin(admin_api)
    headers = {"X-CSRF-Token": csrf}

    created = await admin_api.post(
        "/api/v1/users",
        json={"username": "reader.one", "display_name": "Reader One", "roles": ["reader"]},
        headers=headers,
    )
    assert created.status_code == 201
    payload = created.json()
    assert payload["temporary_password"]
    assert payload["must_change_password"] is True
    user_id = payload["id"]
    assert created.headers["etag"] == 'W/"1"'

    listing = await admin_api.get("/api/v1/users", params={"role": "reader"})
    assert listing.status_code == 200
    assert [item["username"] for item in listing.json()["items"]] == ["reader.one"]

    missing_etag = await admin_api.patch(
        f"/api/v1/users/{user_id}",
        json={"display_name": "Reader Primary"},
        headers=headers,
    )
    assert missing_etag.status_code == 428

    changed = await admin_api.patch(
        f"/api/v1/users/{user_id}",
        json={"display_name": "Reader Primary", "roles": ["editor"]},
        headers={**headers, "If-Match": created.headers["etag"]},
    )
    assert changed.status_code == 200
    assert changed.json()["roles"] == ["editor"]
    assert changed.headers["etag"] == 'W/"2"'

    stale = await admin_api.patch(
        f"/api/v1/users/{user_id}",
        json={"status": "disabled"},
        headers={**headers, "If-Match": created.headers["etag"]},
    )
    assert stale.status_code == 409

    reset = await admin_api.post(
        f"/api/v1/users/{user_id}/reset-password",
        headers=headers,
    )
    assert reset.status_code == 200
    assert reset.json()["temporary_password"]
    assert reset.json()["must_change_password"] is True

    admin = await admin_api.get("/api/v1/users")
    admin_id = next(
        item["id"] for item in admin.json()["items"] if item["username"] == ADMIN_USERNAME
    )
    admin_detail = await admin_api.get(f"/api/v1/users/{admin_id}")
    cannot_disable_last_admin = await admin_api.patch(
        f"/api/v1/users/{admin_id}",
        json={"status": "disabled"},
        headers={**headers, "If-Match": admin_detail.headers["etag"]},
    )
    assert cannot_disable_last_admin.status_code == 422
    assert "last active admin" in cannot_disable_last_admin.json()["detail"]


@pytest.mark.asyncio
async def test_group_lifecycle_and_membership(admin_api: httpx.AsyncClient) -> None:
    csrf = await _login_admin(admin_api)
    headers = {"X-CSRF-Token": csrf}
    user = await admin_api.post(
        "/api/v1/users",
        json={"username": "group.member", "display_name": "Group Member", "roles": ["reader"]},
        headers=headers,
    )
    assert user.status_code == 201
    user_id = user.json()["id"]

    created = await admin_api.post(
        "/api/v1/groups",
        json={"name": "Finance", "description": "Finance team"},
        headers=headers,
    )
    assert created.status_code == 201
    group_id = created.json()["id"]
    assert created.headers["etag"] == 'W/"1"'

    replaced = await admin_api.put(
        f"/api/v1/groups/{group_id}/members",
        json={"user_ids": [user_id]},
        headers=headers,
    )
    assert replaced.status_code == 200
    assert replaced.json()["user_ids"] == [user_id]
    assert replaced.headers["etag"] == 'W/"2"'

    changed = await admin_api.patch(
        f"/api/v1/groups/{group_id}",
        json={"name": "Finance Team"},
        headers={**headers, "If-Match": replaced.headers["etag"]},
    )
    assert changed.status_code == 200
    assert changed.json()["name"] == "Finance Team"
    assert changed.headers["etag"] == 'W/"3"'

    deleted = await admin_api.delete(
        f"/api/v1/groups/{group_id}",
        headers={**headers, "If-Match": changed.headers["etag"]},
    )
    assert deleted.status_code == 204
    assert (await admin_api.get(f"/api/v1/groups/{group_id}")).status_code == 404


@pytest.mark.asyncio
async def test_non_admin_cannot_manage_users(admin_api: httpx.AsyncClient) -> None:
    csrf = await _login_admin(admin_api)
    created = await admin_api.post(
        "/api/v1/users",
        json={"username": "not.admin", "display_name": "Not Admin", "roles": ["reader"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201
    response = await admin_api.post(
        "/api/v1/auth/logout",
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 204
    login = await admin_api.post(
        "/api/v1/auth/login",
        json={
            "username": "not.admin",
            "password": created.json()["temporary_password"],
        },
    )
    assert login.status_code == 200
    denied = await admin_api.get("/api/v1/users")
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_temporary_password_blocks_other_authenticated_actions(
    admin_api: httpx.AsyncClient,
) -> None:
    admin_csrf = await _login_admin(admin_api)
    created = await admin_api.post(
        "/api/v1/users",
        json={"username": "must.change", "display_name": "Must Change", "roles": ["reader"]},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert created.status_code == 201
    login = await admin_api.post(
        "/api/v1/auth/login",
        json={
            "username": "must.change",
            "password": created.json()["temporary_password"],
        },
    )
    assert login.status_code == 200
    csrf = login.json()["csrf_token"]
    blocked = await admin_api.post(
        "/api/v1/auth/totp/enroll",
        headers={"X-CSRF-Token": csrf},
    )
    assert blocked.status_code == 403
    assert blocked.json()["code"] == "PASSWORD_CHANGE_REQUIRED"

    changed = await admin_api.post(
        "/api/v1/auth/password",
        json={
            "current_password": created.json()["temporary_password"],
            "new_password": "different long password",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert changed.status_code == 204
    enrollment = await admin_api.post(
        "/api/v1/auth/totp/enroll",
        headers={"X-CSRF-Token": csrf},
    )
    assert enrollment.status_code == 200


@pytest.mark.asyncio
async def test_doc_type_tree_admin_crud_and_two_level_guard(
    admin_api: httpx.AsyncClient,
) -> None:
    csrf = await _login_admin(admin_api)
    headers = {"X-CSRF-Token": csrf}

    tree = await admin_api.get("/api/v1/doc-types")
    assert tree.status_code == 200

    parent_response = await admin_api.post(
        "/api/v1/doc-types",
        json={"code": "test_parent", "name": "Test parent"},
        headers=headers,
    )
    assert parent_response.status_code == 201

    category_response = await admin_api.post(
        "/api/v1/doc-types",
        json={"code": "test_category", "name": "Test category"},
        headers=headers,
    )
    assert category_response.status_code == 201
    category = category_response.json()
    assert category_response.headers["etag"] == 'W/"1"'

    type_response = await admin_api.post(
        "/api/v1/doc-types",
        json={
            "code": "test_type",
            "name": "Test type",
            "parent_id": category["id"],
            "purpose": "Integration test",
        },
        headers=headers,
    )
    assert type_response.status_code == 201
    doc_type = type_response.json()
    assert doc_type["purpose"] == "Integration test"

    category_with_child = await admin_api.patch(
        f"/api/v1/doc-types/{category['id']}",
        json={"parent_id": parent_response.json()["id"]},
        headers={**headers, "If-Match": category_response.headers["etag"]},
    )
    assert category_with_child.status_code == 409

    changed = await admin_api.patch(
        f"/api/v1/doc-types/{doc_type['id']}",
        json={"name": "Renamed type", "retention_months": 24},
        headers={**headers, "If-Match": type_response.headers["etag"]},
    )
    assert changed.status_code == 200
    assert changed.headers["etag"] == 'W/"2"'
    assert changed.json()["name"] == "Renamed type"
    assert changed.json()["retention_months"] == 24

    stale = await admin_api.patch(
        f"/api/v1/doc-types/{doc_type['id']}",
        json={"name": "Stale update"},
        headers={**headers, "If-Match": type_response.headers["etag"]},
    )
    assert stale.status_code == 409

    nested_tree = await admin_api.get("/api/v1/doc-types")
    returned_category = next(item for item in nested_tree.json() if item["id"] == category["id"])
    assert [item["id"] for item in returned_category["types"]] == [doc_type["id"]]

    deleted_type = await admin_api.delete(
        f"/api/v1/doc-types/{doc_type['id']}",
        headers={**headers, "If-Match": changed.headers["etag"]},
    )
    assert deleted_type.status_code == 204
    deleted_category = await admin_api.delete(
        f"/api/v1/doc-types/{category['id']}",
        headers={**headers, "If-Match": category_response.headers["etag"]},
    )
    assert deleted_category.status_code == 204
    deleted_parent = await admin_api.delete(
        f"/api/v1/doc-types/{parent_response.json()['id']}",
        headers={**headers, "If-Match": parent_response.headers["etag"]},
    )
    assert deleted_parent.status_code == 204
