from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import fitz
import httpx
import pytest
import pytest_asyncio
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.api.printing import recover_interrupted_print_jobs
from app.core.config import Settings
from app.db import migrate
from app.db.enums import PrintStatus, RoleName
from app.db.models.documents import Document, DocumentVersion
from app.db.models.operations import AuditEvent, PrintItem, PrintJob, Rendition
from app.db.seed import seed_catalogue
from app.main import create_app
from app.services.auth import create_user
from app.vault.blobs import decrypt_blob
from app.vault.init import InitResult
from app.vault.session import VaultManager

from .conftest import Pair

PASSWORD = "correct horse battery staple"


@pytest_asyncio.fixture
async def document_client(
    pair: Pair,
    vault: tuple[Path, str, InitResult],
    settings: Settings,
) -> AsyncIterator[tuple[httpx.AsyncClient, VaultManager, str, str]]:
    migrate.upgrade(pair.dsn)
    engine = create_engine(pair.dsn)
    root, passphrase, _ = vault
    manager = VaultManager(root, app_version="0.1.0-test")
    manager.open()
    manager.unlock(passphrase)
    with engine.begin() as connection:
        seed_catalogue(connection, meta_key=manager.keys.meta_key)
    username = f"upload-{uuid.uuid4().hex[:8]}"
    with Session(engine) as session, session.begin():
        create_user(
            session,
            manager.keys,
            username=username,
            display_name="Upload Operator",
            password=PASSWORD,
            roles=(RoleName.ADMIN,),
            actor_id=None,
            source_ip="127.0.0.1",
            must_change_password=False,
        )
    app = create_app(settings, vault=manager, db_engine=engine)
    app.state.vault = manager
    app.state.db_engine = engine
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 43123)),
        base_url="https://testserver",
    )
    try:
        yield client, manager, username, pair.dsn
    finally:
        await client.aclose()
        manager.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_upload_api_encrypts_directly_to_vault_and_records_version(  # noqa: PLR0915
    document_client: tuple[httpx.AsyncClient, VaultManager, str, str],
) -> None:
    client, manager, username, dsn = document_client
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": PASSWORD},
    )
    assert login.status_code == 200
    csrf = login.json()["csrf_token"]
    entity_response = await client.post(
        "/api/v1/entities",
        headers={"X-CSRF-Token": csrf},
        json={
            "entity_type": "company",
            "legal_name": "Example Holdings",
            "identifiers": [{"id_type": "pan", "value": "AABCA1234B"}],
        },
    )
    assert entity_response.status_code == 201, entity_response.text
    entity = entity_response.json()
    assert entity["identifiers"][0]["value"] is None
    assert entity["identifiers"][0]["value_masked"] == "AA******4B"
    entity_patch = await client.patch(
        f"/api/v1/entities/{entity['id']}",
        headers={"X-CSRF-Token": csrf, "If-Match": entity_response.headers["etag"]},
        json={"display_name": "Example"},
    )
    assert entity_patch.status_code == 200, entity_patch.text
    assert entity_patch.json()["display_name"] == "Example"

    office_rejected = await client.post(
        "/api/v1/documents",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "office-converter-unavailable"},
        files={
            "metadata": (
                None,
                json.dumps(
                    {
                        "title": "Office document",
                        "doc_type_code": "pan_card",
                        "entity_links": [{"entity_id": entity["id"], "link_role": "belongs_to"}],
                    }
                ),
                "application/json",
            ),
            "file": ("sample.docx", b"PK\x03\x04unconverted", "application/octet-stream"),
        },
    )
    assert office_rejected.status_code == 415

    pdf_document = fitz.open()
    pdf_page = pdf_document.new_page()
    pdf_page.insert_text((72, 72), "Original document")
    pdf = pdf_document.tobytes()
    pdf_document.close()
    response = await client.post(
        "/api/v1/documents",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "document-upload-once"},
        files={
            "metadata": (
                None,
                json.dumps(
                    {
                        "title": "PAN Scan",
                        "doc_type_code": "pan_card",
                        "entity_links": [{"entity_id": entity["id"], "link_role": "belongs_to"}],
                    }
                ),
                "application/json",
            ),
            "file": ("sample.pdf", pdf, "application/pdf"),
        },
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["title"] == "PAN Scan"
    assert body["version"]["version_no"] == 1
    assert body["version"]["plaintext_size"] == len(pdf)
    assert body["version"]["mime"] == "application/pdf"
    assert body["version"]["derived_pdf"] is None
    assert response.headers["etag"] == 'W/"1"'
    assert response.headers["location"] == f"/api/v1/documents/{body['id']}"
    tag_added = await client.post(
        f"/api/v1/documents/{body['id']}/tags",
        headers={"X-CSRF-Token": csrf, "If-Match": 'W/"1"'},
        json={"name": "Reviewed", "color": "#2A6F97"},
    )
    assert tag_added.status_code == 204
    assert tag_added.headers["etag"] == 'W/"2"'
    assert any(tag["name"] == "reviewed" for tag in (await client.get("/api/v1/tags")).json())
    tag_removed = await client.request(
        "DELETE",
        f"/api/v1/documents/{body['id']}/tags",
        headers={"X-CSRF-Token": csrf, "If-Match": 'W/"2"'},
        json={"name": "REVIEWED"},
    )
    assert tag_removed.status_code == 204
    assert tag_removed.headers["etag"] == 'W/"3"'
    repeated_link = await client.post(
        f"/api/v1/documents/{body['id']}/links",
        headers={"X-CSRF-Token": csrf, "If-Match": 'W/"3"'},
        json={"entity_id": entity["id"], "link_role": "belongs_to"},
    )
    assert repeated_link.status_code == 204
    assert repeated_link.headers["etag"] == 'W/"3"'
    engine = create_engine(dsn)
    try:
        with Session(engine) as session:
            version_id = session.scalar(
                select(DocumentVersion.id).where(
                    DocumentVersion.document_id == uuid.UUID(body["id"]),
                    DocumentVersion.version_no == 1,
                )
            )
    finally:
        engine.dispose()
    assert version_id is not None
    assert body["version"]["id"] == str(version_id)
    print_response = await client.post(
        "/api/v1/print-jobs",
        headers={"X-CSRF-Token": csrf},
        json={"items": [{"version_id": str(version_id), "pages": "1"}]},
    )
    assert print_response.status_code == 200, print_response.text
    assert print_response.headers["content-type"] == "application/pdf"
    assert print_response.headers["cache-control"] == "no-store"
    print_job_id = print_response.headers["x-print-job-id"]
    print_job_response = await client.get(f"/api/v1/print-jobs/{print_job_id}")
    assert print_job_response.status_code == 200
    assert print_job_response.json()["status"] == "completed"
    assert print_job_response.json()["items"][0]["pages"] == "1"
    print_jobs_response = await client.get("/api/v1/print-jobs")
    assert print_jobs_response.status_code == 200
    assert [job["id"] for job in print_jobs_response.json()] == [print_job_id]
    printed = fitz.open(stream=print_response.content, filetype="pdf")
    try:
        assert printed.page_count == 1
        assert "Original document" in printed[0].get_text()
    finally:
        printed.close()
    invalid_print = await client.post(
        "/api/v1/print-jobs",
        headers={"X-CSRF-Token": csrf},
        json={"items": [{"version_id": str(version_id), "pages": "1-2"}]},
    )
    assert invalid_print.status_code == 422
    engine = create_engine(dsn)
    try:
        with Session(engine) as session:
            print_job = session.scalar(select(PrintJob))
            print_item = session.scalar(select(PrintItem))
            assert print_job is not None
            assert print_job.status.value == "completed"
            assert print_job.page_count == 1
            assert print_job.sheet_count == 1
            assert print_item is not None
            assert print_item.page_from == 1
            assert print_item.page_to == 1
            print_audit = session.scalar(
                select(AuditEvent).where(
                    AuditEvent.object_id == print_job.id,
                    AuditEvent.action == "print_job.create",
                )
            )
            assert print_audit is not None
            assert print_audit.detail["layout"]["paper"] == "A4"
            assert print_audit.detail["items"][0]["document_id"] == str(print_item.document_id)
            assert print_audit.detail["items"][0]["ranges"] == ["1"]
            crashed_job = PrintJob(
                requested_by=print_job.requested_by,
                paper="A4",
                orientation="portrait",
                cells_per_side=1,
                duplex=False,
                flip_edge=None,
                margin_mm=5,
                gutter_mm=4,
                fit_mode="contain",
                item_count=0,
                page_count=0,
                sheet_count=0,
                status=PrintStatus.INTERRUPTED,
                source_ip="127.0.0.1",
            )
            session.add(crashed_job)
            session.flush()
            crashed_job_id = crashed_job.id
            session.commit()

        assert recover_interrupted_print_jobs(engine) == 1
        with Session(engine) as session:
            recovered_job = session.get(PrintJob, crashed_job_id)
            assert recovered_job is not None
            assert recovered_job.status == PrintStatus.FAILED
            assert recovered_job.completed_at is not None
            recovery_audit = session.scalar(
                select(AuditEvent).where(
                    AuditEvent.object_id == crashed_job_id,
                    AuditEvent.action == "print_job.create",
                    AuditEvent.outcome == "error",
                )
            )
            assert recovery_audit is not None
            assert recovery_audit.detail["error_code"] == "process_interrupted"
    finally:
        engine.dispose()
    revised_document = fitz.open()
    revised_page = revised_document.new_page()
    revised_page.insert_text((72, 72), "Revised document")
    revised_pdf = revised_document.tobytes()
    revised_document.close()
    version_response = await client.post(
        f"/api/v1/documents/{body['id']}/versions",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "document-version-two"},
        files={
            "metadata": (None, json.dumps({"note": "Revised scan"}), "application/json"),
            "file": ("revised.pdf", revised_pdf, "application/pdf"),
        },
    )
    assert version_response.status_code == 201, version_response.text
    assert version_response.json()["version_no"] == 2
    assert version_response.json()["plaintext_size"] == len(revised_pdf)
    assert version_response.json()["mime"] == "application/pdf"
    assert version_response.json()["derived_pdf"] is None
    replay_version = await client.post(
        f"/api/v1/documents/{body['id']}/versions",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "document-version-two"},
        files={
            "metadata": (None, json.dumps({"note": "Revised scan"}), "application/json"),
            "file": ("revised.pdf", revised_pdf, "application/pdf"),
        },
    )
    assert replay_version.status_code == 201
    assert replay_version.json() == version_response.json()
    mismatched_version_document = fitz.open()
    mismatched_version_page = mismatched_version_document.new_page()
    mismatched_version_page.insert_text((72, 72), "Different version data")
    mismatched_version_pdf = mismatched_version_document.tobytes()
    mismatched_version_document.close()
    mismatched_replay = await client.post(
        f"/api/v1/documents/{body['id']}/versions",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "document-version-two"},
        files={
            "metadata": (None, json.dumps({"note": "Revised scan"}), "application/json"),
            "file": ("revised.pdf", mismatched_version_pdf, "application/pdf"),
        },
    )
    assert mismatched_replay.status_code == 409
    versions = await client.get(f"/api/v1/documents/{body['id']}/versions")
    assert versions.status_code == 200
    assert [version["version_no"] for version in versions.json()] == [1, 2]
    current_document = await client.get(f"/api/v1/documents/{body['id']}")
    assert current_document.json()["version"]["version_no"] == 2
    linked_documents = await client.get(f"/api/v1/entities/{entity['id']}/documents")
    assert linked_documents.status_code == 200
    assert linked_documents.json()["items"][0]["id"] == body["id"]
    category_documents = await client.get("/api/v1/documents?category=identity")
    assert category_documents.status_code == 200
    assert category_documents.json()["items"][0]["id"] == body["id"]
    title_search = await client.get("/api/v1/documents", params={"q": "AN SC"})
    assert title_search.status_code == 200
    assert [item["id"] for item in title_search.json()["items"]] == [body["id"]]
    render_settings = await client.put(
        f"/api/v1/documents/{body['id']}/versions/1/render-settings",
        headers={"X-CSRF-Token": csrf, "If-Match": 'W/"0"'},
        json={"grayscale": True},
    )
    assert render_settings.status_code == 200, render_settings.text
    assert render_settings.headers["etag"] == 'W/"1"'
    rendition_ticket = await client.post(
        f"/api/v1/documents/{body['id']}/versions/1/renditions",
        headers={"X-CSRF-Token": csrf},
        json={
            "page": 1,
            "kind": "preview",
            "recipe": {"grayscale": True},
            "break_glass_reason": "Validation of secure rendition",
        },
    )
    assert rendition_ticket.status_code == 200, rendition_ticket.text
    assert rendition_ticket.json()["page_count"] == 1
    rendition = await client.get(
        rendition_ticket.json()["url"],
        headers={"X-Break-Glass-Reason": "Validation of secure rendition"},
    )
    assert rendition.status_code == 200
    assert rendition.headers["content-type"] == "image/png"
    assert rendition.content.startswith(b"\x89PNG\r\n\x1a\n")
    rendition_replay = await client.get(
        rendition_ticket.json()["url"],
        headers={"X-Break-Glass-Reason": "Validation of secure rendition"},
    )
    assert rendition_replay.status_code == 410
    mismatched_initial_document = fitz.open()
    mismatched_initial_page = mismatched_initial_document.new_page()
    mismatched_initial_page.insert_text((72, 72), "Different initial data")
    mismatched_initial_pdf = mismatched_initial_document.tobytes()
    mismatched_initial_document.close()
    replay = await client.post(
        "/api/v1/documents",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "document-upload-once"},
        files={
            "metadata": (
                None,
                json.dumps(
                    {
                        "title": "PAN Scan",
                        "doc_type_code": "pan_card",
                        "entity_links": [{"entity_id": entity["id"], "link_role": "belongs_to"}],
                    }
                ),
                "application/json",
            ),
            "file": ("sample.pdf", mismatched_initial_pdf, "application/pdf"),
        },
    )
    assert replay.status_code == 409
    matching_replay = await client.post(
        "/api/v1/documents",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "document-upload-once"},
        files={
            "metadata": (
                None,
                json.dumps(
                    {
                        "title": "PAN Scan",
                        "doc_type_code": "pan_card",
                        "entity_links": [{"entity_id": entity["id"], "link_role": "belongs_to"}],
                    }
                ),
                "application/json",
            ),
            "file": ("sample.pdf", pdf, "application/pdf"),
        },
    )
    assert matching_replay.status_code == 201
    assert matching_replay.json() == body

    engine = create_engine(dsn)
    try:
        with Session(engine) as session:
            version = session.scalar(
                select(DocumentVersion).where(DocumentVersion.document_id == uuid.UUID(body["id"]))
            )
            assert version is not None
            encrypted = manager.paths.blob(version.blob_addr).read_bytes()
            assert pdf not in encrypted
            decrypted = decrypt_blob(
                encrypted,
                manager.keys,
                salt=version.blob_salt,
                expected_address=version.blob_addr,
            )
            assert decrypted.plaintext == pdf

        ticket_response = await client.post(
            f"/api/v1/documents/{body['id']}/versions/1/download-ticket",
            headers={"X-CSRF-Token": csrf},
            json={"break_glass_reason": "Validation of secure download"},
        )
        assert ticket_response.status_code == 200, ticket_response.text
        ticket_url = ticket_response.json()["url"]
        download = await client.get(
            ticket_url,
            headers={"X-Break-Glass-Reason": "Validation of secure download"},
        )
        assert download.status_code == 200, download.text
        assert download.content == pdf
        assert download.headers["cache-control"] == "no-store"
        assert download.headers["content-disposition"].startswith("attachment;")
        repeated = await client.get(
            ticket_url,
            headers={"X-Break-Glass-Reason": "Validation of secure download"},
        )
        assert repeated.status_code == 410

        range_ticket = await client.post(
            f"/api/v1/documents/{body['id']}/versions/1/download-ticket",
            headers={"X-CSRF-Token": csrf},
            json={"break_glass_reason": "Validation of ranged download"},
        )
        range_url = range_ticket.json()["url"]
        invalid_range = await client.get(
            range_url,
            headers={
                "X-Break-Glass-Reason": "Validation of ranged download",
                "Range": f"bytes={len(pdf)}-",
            },
        )
        assert invalid_range.status_code == 416
        assert invalid_range.headers["content-range"] == f"bytes */{len(pdf)}"
        partial = await client.get(
            range_url,
            headers={
                "X-Break-Glass-Reason": "Validation of ranged download",
                "Range": "bytes=0-4",
            },
        )
        assert partial.status_code == 206
        assert partial.content == pdf[:5]
        assert partial.headers["content-range"] == f"bytes 0-4/{len(pdf)}"
        assert partial.headers["accept-ranges"] == "bytes"

        current_document = await client.get(f"/api/v1/documents/{body['id']}")
        delete_response = await client.delete(
            f"/api/v1/documents/{body['id']}",
            headers={
                "X-CSRF-Token": csrf,
                "If-Match": current_document.headers["etag"],
            },
        )
        assert delete_response.status_code == 204
        with Session(engine) as session, session.begin():
            document = session.get(Document, uuid.UUID(body["id"]))
            assert document is not None
            document.legal_hold = True
        blocked_purge = await client.post(
            f"/api/v1/documents/{body['id']}/purge",
            headers={"X-CSRF-Token": csrf},
            json={"reason": "Approved records disposal"},
        )
        assert blocked_purge.status_code == 409
        with Session(engine) as session, session.begin():
            document = session.get(Document, uuid.UUID(body["id"]))
            assert document is not None
            document.legal_hold = False
            document.purge_after = datetime.now(UTC).date() - timedelta(days=1)
        purge_response = await client.post(
            f"/api/v1/documents/{body['id']}/purge",
            headers={"X-CSRF-Token": csrf},
            json={"reason": "Approved records disposal"},
        )
        assert purge_response.status_code == 204, purge_response.text
        with Session(engine) as session:
            document = session.get(Document, uuid.UUID(body["id"]))
            versions_after_purge = list(
                session.scalars(
                    select(DocumentVersion).where(
                        DocumentVersion.document_id == uuid.UUID(body["id"])
                    )
                )
            )
            renditions_after_purge = list(session.scalars(select(Rendition)))
            assert document is not None
            assert document.purged_at is not None
            assert len(versions_after_purge) == 2
            assert all(version.purged_at is not None for version in versions_after_purge)
        assert all(
            not manager.paths.blob(version.blob_addr).exists() for version in versions_after_purge
        )
        assert not renditions_after_purge
    finally:
        engine.dispose()
