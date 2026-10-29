from __future__ import annotations

import json
from pathlib import Path

import pytest
from starlette.requests import Request

from app.api.documents import UploadMetadata, _stream_multipart
from app.core.errors import DocVaultError
from app.crypto.keys import VaultKeys
from app.vault.blobs import decrypt_blob


def _request(body: bytes, boundary: str) -> Request:
    sent = False

    async def receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/api/v1/documents",
            "raw_path": b"/api/v1/documents",
            "query_string": b"",
            "headers": [
                (b"content-type", f"multipart/form-data; boundary={boundary}".encode()),
                (b"content-length", str(len(body)).encode()),
            ],
            "client": ("127.0.0.1", 43123),
            "server": ("testserver", 443),
        },
        receive=receive,
    )


def _body(filename: str, payload: bytes, *, boundary: str = "docvault-test") -> bytes:
    metadata = json.dumps({"title": "Scan", "doc_type_code": "proof"}).encode()
    return (
        (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="metadata"\r\n'
            "Content-Type: application/json\r\n\r\n"
        ).encode()
        + metadata
        + (
            f"\r\n--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + payload
        + f"\r\n--{boundary}--\r\n".encode()
    )


@pytest.mark.asyncio
async def test_multipart_upload_encrypts_as_it_streams(keys: VaultKeys, tmp_path: Path) -> None:
    payload = b"%PDF-1.7\nsafe content"
    temporary_path = tmp_path / "upload.part"

    uploaded = await _stream_multipart(
        _request(_body("scan.pdf", payload), "docvault-test"),
        keys=keys,
        max_file_bytes=1024,
        temporary_path=temporary_path,
        metadata_model=UploadMetadata,
        validate_metadata=lambda _metadata: None,
    )

    opened = decrypt_blob(
        temporary_path.read_bytes(),
        keys,
        salt=uploaded.salt,
        expected_address=uploaded.address,
    )
    assert uploaded.metadata == UploadMetadata(title="Scan", doc_type_code="proof")
    assert uploaded.filename == "scan.pdf"
    assert uploaded.mime == "application/pdf"
    assert opened.plaintext == payload
    assert payload not in temporary_path.read_bytes()


@pytest.mark.asyncio
async def test_multipart_upload_rejects_non_document_content(
    keys: VaultKeys, tmp_path: Path
) -> None:
    temporary_path = tmp_path / "upload.part"

    with pytest.raises(DocVaultError) as caught:
        await _stream_multipart(
            _request(_body("scan.pdf", b"#!/bin/sh\nmalware"), "docvault-test"),
            keys=keys,
            max_file_bytes=1024,
            temporary_path=temporary_path,
            metadata_model=UploadMetadata,
            validate_metadata=lambda _metadata: None,
        )

    assert caught.value.code == "UNSUPPORTED_MEDIA_TYPE"
    assert not temporary_path.exists()


@pytest.mark.asyncio
async def test_multipart_upload_enforces_limit_and_cleans_partial_blob(
    keys: VaultKeys, tmp_path: Path
) -> None:
    temporary_path = tmp_path / "oversized.part"

    with pytest.raises(DocVaultError) as caught:
        await _stream_multipart(
            _request(_body("scan.pdf", b"%PDF-1.7\ncontent"), "docvault-test"),
            keys=keys,
            max_file_bytes=8,
            temporary_path=temporary_path,
            metadata_model=UploadMetadata,
            validate_metadata=lambda _metadata: None,
        )

    assert caught.value.code == "PAYLOAD_TOO_LARGE"
    assert not temporary_path.exists()


@pytest.mark.asyncio
async def test_multipart_upload_rejects_active_pdf_content(keys: VaultKeys, tmp_path: Path) -> None:
    temporary_path = tmp_path / "active.part"

    with pytest.raises(DocVaultError) as caught:
        await _stream_multipart(
            _request(
                _body("active.pdf", b"%PDF-1.7\n/OpenAction /JavaScript"),
                "docvault-test",
            ),
            keys=keys,
            max_file_bytes=1024,
            temporary_path=temporary_path,
            metadata_model=UploadMetadata,
            validate_metadata=lambda _metadata: None,
        )

    assert caught.value.code == "UNSUPPORTED_MEDIA_TYPE"
    assert not temporary_path.exists()
