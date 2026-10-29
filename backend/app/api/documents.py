"""Document metadata and encrypted upload endpoints."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
import unicodedata
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Cookie, Header, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from python_multipart import MultipartParser
from python_multipart.exceptions import MultipartParseError
from python_multipart.multipart import parse_options_header
from sqlalchemy import delete, func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.sql import Select

from app.core.errors import DocVaultError
from app.crypto.canonical import canonical_json
from app.crypto.keys import VaultKeys, blind_index, decrypt_column, encrypt_column
from app.db.enums import AclMode, ConfLevel, DocStatus, LinkRole, RoleName, SideKind
from app.db.models.documents import (
    DocType,
    Document,
    DocumentEntityLink,
    DocumentTag,
    DocumentVersion,
    Tag,
    VersionRenderSettings,
)
from app.db.models.operations import DownloadTicket, IdempotencyKey, Rendition
from app.render.worker_client import convert_office, inspect_pdf, render_page
from app.services import acl, auth
from app.services.audit import append_event
from app.vault.blobs import (
    BlobStreamWriter,
    decrypt_blob,
    encrypt_blob,
    read_blob_file,
    write_blob_file,
)
from app.vault.session import VaultManager

router = APIRouter(prefix="/api/v1", tags=["documents"])
PDF_ACTIVE_CONTENT = re.compile(
    rb"/(?:JavaScript|JS|Launch|EmbeddedFiles?|OpenAction|AA)(?![A-Za-z0-9])",
    re.IGNORECASE,
)
OFFICE_MIMES = {
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.oasis.opendocument.text",
}
MAX_METADATA_BYTES = 64 * 1024
MAX_MULTIPART_OVERHEAD = 256 * 1024
MAX_SEARCH_CANDIDATES = 10_000
DOC_TYPE_TREE_LOCK = 0x444F435459504553


class EntityLinkInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_id: uuid.UUID
    link_role: LinkRole


class TagInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    color: str | None = Field(default=None, pattern=r"^#[0-9a-fA-F]{6}$")


class TagResponse(BaseModel):
    id: uuid.UUID
    name: str
    color: str | None
    is_system: bool


class DocTypeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(pattern=r"^[a-z][a-z0-9_]{0,127}$")
    name: str = Field(min_length=1, max_length=200)
    parent_id: uuid.UUID | None = None
    default_confidentiality: ConfLevel = ConfLevel.NORMAL
    retention_months: int | None = Field(default=None, gt=0)
    requires_expiry: bool = False
    side: SideKind | None = None
    purpose: str | None = Field(default=None, max_length=1000)
    sort_order: int = 0


class DocTypePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=200)
    parent_id: uuid.UUID | None = None
    default_confidentiality: ConfLevel | None = None
    retention_months: int | None = Field(default=None, gt=0)
    requires_expiry: bool | None = None
    side: SideKind | None = None
    purpose: str | None = Field(default=None, max_length=1000)
    sort_order: int | None = None


class DocTypeResponse(BaseModel):
    id: uuid.UUID
    code: str
    name: str
    parent_id: uuid.UUID | None
    default_confidentiality: ConfLevel
    retention_months: int | None
    requires_expiry: bool
    side: SideKind | None
    purpose: str | None
    is_system: bool
    sort_order: int
    row_version: int


class DocTypeCategory(DocTypeResponse):
    types: list[DocTypeResponse]


class UploadMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=300)
    doc_type_code: str = Field(min_length=1, max_length=128)
    entity_links: tuple[EntityLinkInput, ...] = Field(default=(), max_length=50)
    issue_date: date | None = None
    expiry_date: date | None = None
    confidentiality: ConfLevel | None = None
    acl_mode: AclMode = AclMode.INHERIT
    tags: tuple[str, ...] = Field(default=(), max_length=20)


class VersionUploadMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str | None = Field(default=None, max_length=500)


class VersionResponse(BaseModel):
    id: uuid.UUID
    version_no: int
    plaintext_size: int
    mime: str
    derived_pdf: dict[str, int] | None = None


def _derived_pdf_info(version: DocumentVersion) -> dict[str, int] | None:
    if version.derived_pdf_addr is None:
        return None
    if version.derived_pdf_pages is None or version.derived_pdf_size is None:
        raise DocVaultError("BLOB_INVALID", detail="The derived PDF metadata is incomplete.")
    return {"pages": version.derived_pdf_pages, "size": version.derived_pdf_size}


class DocumentResponse(BaseModel):
    id: uuid.UUID
    title: str
    doc_type_id: uuid.UUID
    issue_date: date | None
    expiry_date: date | None
    confidentiality: ConfLevel
    status: DocStatus
    row_version: int
    version: VersionResponse


class DocumentListResponse(BaseModel):
    items: list[DocumentResponse]
    next_cursor: str | None


class DownloadTicketResponse(BaseModel):
    url: str
    expires_at: datetime
    filename: str


class DownloadTicketRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    break_glass_reason: str | None = Field(default=None, max_length=500)


class PurgeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=10, max_length=500)


class DocumentPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, max_length=300)
    issue_date: date | None = None
    expiry_date: date | None = None
    confidentiality: ConfLevel | None = None


@dataclass(slots=True)
class UploadResult[UploadModel: BaseModel]:
    metadata: UploadModel
    filename: str
    mime: str
    file_hash: bytes
    address: str
    salt: bytes
    plaintext_size: int
    temporary_path: Path


@dataclass(slots=True)
class DerivedPDFBlob:
    address: str
    salt: bytes
    page_count: int
    plaintext_size: int
    path: Path


def _engine(request: Request) -> Engine:
    engine = getattr(request.app.state, "db_engine", None)
    if not isinstance(engine, Engine):
        raise DocVaultError("DB_UNAVAILABLE", detail="The database is not configured.")
    return engine


def _vault(request: Request) -> VaultManager:
    vault = getattr(request.app.state, "vault", None)
    if not isinstance(vault, VaultManager):
        raise DocVaultError("NOT_READY", detail="The vault is not open.")
    return vault


def _office_converter(request: Request) -> Path | None:
    settings = getattr(request.app.state, "settings", None)
    configured = getattr(getattr(settings, "office", None), "convert_exe", None)
    if (
        not isinstance(configured, Path)
        or not configured.is_file()
        or not os.access(configured, os.X_OK)
    ):
        return None
    return configured


def _validate_uploaded_content[UploadModel: BaseModel](
    uploaded: UploadResult[UploadModel],
    *,
    keys: VaultKeys,
    vault: VaultManager,
    office_converter: Path | None,
) -> DerivedPDFBlob | None:
    plaintext = decrypt_blob(
        read_blob_file(uploaded.temporary_path),
        keys,
        salt=uploaded.salt,
        expected_address=uploaded.address,
    ).plaintext
    try:
        if uploaded.mime not in OFFICE_MIMES:
            if uploaded.mime == "application/pdf":
                inspect_pdf(plaintext)
            else:
                render_page(
                    plaintext,
                    mime=uploaded.mime,
                    page=1,
                    recipe={},
                    max_edge=1,
                )
            return None
        if office_converter is None:
            raise DocVaultError(
                "UNSUPPORTED_MEDIA_TYPE",
                detail="Office conversion is unavailable on this server.",
            )
        converted_pdf = convert_office(
            plaintext,
            filename=uploaded.filename,
            converter=office_converter,
        )
        details = inspect_pdf(converted_pdf)
    except DocVaultError as exc:
        if exc.code != "BLOB_INVALID":
            raise
        raise DocVaultError(
            "UNSUPPORTED_MEDIA_TYPE",
            detail="The file is malformed or contains unsupported active content.",
        ) from exc

    encrypted = encrypt_blob(converted_pdf, keys)
    path = vault.paths.blob(encrypted.address)
    write_blob_file(encrypted, path, vault.paths.tmp / f"{uuid.uuid4().hex}.part")
    return DerivedPDFBlob(
        address=encrypted.address,
        salt=encrypted.salt,
        page_count=details["page_count"],
        plaintext_size=len(converted_pdf),
        path=path,
    )


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client is not None else None


def _authenticate(
    session: OrmSession,
    keys: VaultKeys,
    token: str | None,
    csrf: str | None,
) -> auth.AuthenticatedSession:
    actor = auth.authenticate(session, keys, token)
    auth.verify_csrf(session, token, csrf)
    return actor


def _metadata_error(exc: ValidationError) -> DocVaultError:
    fields = [
        {
            "field": ".".join(str(part) for part in error["loc"]),
            "code": str(error["type"]),
            "message": str(error["msg"]),
        }
        for error in exc.errors()
    ]
    return DocVaultError("VALIDATION_FAILED", fields=fields)


def _validate_metadata(
    session: OrmSession,
    actor: auth.AuthenticatedSession,
    metadata: UploadMetadata,
    source_ip: str | None,
) -> tuple[uuid.UUID, ConfLevel]:
    title = metadata.title.strip()
    if not title:
        raise DocVaultError(
            "VALIDATION_FAILED",
            fields=[{"field": "title", "code": "empty", "message": "A title is required."}],
        )
    normalized_tags = [_normalize_tag_name(tag) for tag in metadata.tags]
    if len(set(normalized_tags)) != len(normalized_tags):
        raise DocVaultError("VALIDATION_FAILED", detail="Tags must be unique.")
    if not metadata.entity_links and not {
        RoleName.ADMIN.value,
        RoleName.EDITOR.value,
    }.intersection(actor.roles):
        raise DocVaultError("FORBIDDEN", detail="The write capability is required.")

    entity_keys = [(link.entity_id, link.link_role) for link in metadata.entity_links]
    if len(entity_keys) != len(set(entity_keys)):
        raise DocVaultError("VALIDATION_FAILED", detail="Entity links must be unique.")
    for link in metadata.entity_links:
        acl.require_entity(
            session,
            actor.user_id,
            link.entity_id,
            acl.WRITE,
            source_ip=source_ip,
        )

    doc_type = session.scalar(select(DocType).where(DocType.code == metadata.doc_type_code))
    if doc_type is None or doc_type.parent_id is None:
        raise DocVaultError(
            "VALIDATION_FAILED",
            fields=[
                {
                    "field": "doc_type_code",
                    "code": "unknown",
                    "message": "Select an active document type under a category.",
                }
            ],
        )
    category = session.get(DocType, doc_type.parent_id)
    if category is None or category.parent_id is not None:
        raise DocVaultError(
            "VALIDATION_FAILED",
            fields=[
                {
                    "field": "doc_type_code",
                    "code": "invalid_category",
                    "message": "The document type is not under a category.",
                }
            ],
        )
    if doc_type.requires_expiry and metadata.expiry_date is None:
        raise DocVaultError(
            "VALIDATION_FAILED",
            fields=[
                {
                    "field": "expiry_date",
                    "code": "required",
                    "message": "This document type requires an expiry date.",
                }
            ],
        )
    if (
        metadata.issue_date is not None
        and metadata.expiry_date is not None
        and metadata.expiry_date < metadata.issue_date
    ):
        raise DocVaultError("VALIDATION_FAILED", detail="expiry_date must not precede issue_date.")

    confidentiality = metadata.confidentiality or doc_type.default_confidentiality
    levels = {
        ConfLevel.NORMAL: 0,
        ConfLevel.SENSITIVE: 1,
        ConfLevel.RESTRICTED: 2,
    }
    if (
        levels[confidentiality] < levels[doc_type.default_confidentiality]
        and RoleName.ADMIN.value not in actor.roles
    ):
        raise DocVaultError(
            "VALIDATION_FAILED",
            fields=[
                {
                    "field": "confidentiality",
                    "code": "below_default",
                    "message": "Only an administrator may lower the document type default.",
                }
            ],
        )
    return doc_type.id, confidentiality


def _sniff_mime(prefix: bytes) -> str | None:
    if prefix.startswith(b"%PDF-"):
        return "application/pdf"
    if prefix.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if prefix.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if prefix.startswith(b"PK\x03\x04"):
        return "application/x-office-zip"
    if prefix.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "application/x-office-ole"
    return None


async def _stream_multipart[UploadModel: BaseModel](  # noqa: PLR0915
    request: Request,
    *,
    keys: VaultKeys,
    max_file_bytes: int,
    temporary_path: Path,
    metadata_model: type[UploadModel],
    validate_metadata: Callable[[UploadModel], None],
    office_converter_available: bool = False,
) -> UploadResult[UploadModel]:
    content_type = request.headers.get("content-type", "")
    media_type, options = parse_options_header(content_type)
    boundary = options.get(b"boundary")
    if media_type.lower() != b"multipart/form-data" or not boundary:
        raise DocVaultError(
            "UNSUPPORTED_MEDIA_TYPE",
            detail="Use multipart/form-data with metadata and file parts.",
        )
    declared_length = request.headers.get("content-length")
    if declared_length is not None:
        try:
            if int(declared_length) > max_file_bytes + MAX_MULTIPART_OVERHEAD:
                raise DocVaultError("PAYLOAD_TOO_LARGE")
        except ValueError as exc:
            raise DocVaultError("BAD_REQUEST", detail="Content-Length is invalid.") from exc

    header_name = bytearray()
    header_value = bytearray()
    headers: dict[bytes, bytes] = {}
    metadata_bytes = bytearray()
    prefix = bytearray()
    scan_tail = b""
    part_name = ""
    filename = ""
    metadata: UploadModel | None = None
    mime = ""
    file_complete = False
    writer: BlobStreamWriter | None = None
    address = ""
    plaintext_size = 0
    writer_salt: bytes | None = None
    file_hasher = hashlib.sha256()

    def on_part_begin() -> None:
        nonlocal headers
        headers = {}

    def on_header_field(data: bytes, start: int, end: int) -> None:
        header_name.extend(data[start:end])

    def on_header_value(data: bytes, start: int, end: int) -> None:
        header_value.extend(data[start:end])

    def on_header_end() -> None:
        headers[bytes(header_name).lower()] = bytes(header_value)
        header_name.clear()
        header_value.clear()

    def on_headers_finished() -> None:
        nonlocal part_name, filename, writer, writer_salt
        disposition, options = parse_options_header(headers.get(b"content-disposition"))
        if disposition.lower() != b"form-data":
            raise DocVaultError("BAD_REQUEST", detail="A multipart part has invalid disposition.")
        name = options.get(b"name")
        if name == b"metadata" and metadata is None:
            if options.get(b"filename") is not None:
                raise DocVaultError("BAD_REQUEST", detail="Metadata must be a JSON form field.")
            part_name = "metadata"
            return
        if name == b"file" and metadata is not None and not file_complete:
            raw_filename = options.get(b"filename")
            if raw_filename is None:
                raise DocVaultError("VALIDATION_FAILED", detail="The file part needs a filename.")
            filename_value = unicodedata.normalize("NFC", raw_filename.decode("utf-8", "replace"))
            filename = filename_value.replace("\\", "/").rsplit("/", 1)[-1].strip()
            if not filename or len(filename) > 255 or any(ord(char) < 32 for char in filename):
                raise DocVaultError("VALIDATION_FAILED", detail="The filename is invalid.")
            if (
                Path(filename).suffix.lower() in {".doc", ".docx", ".odt"}
                and not office_converter_available
            ):
                raise DocVaultError(
                    "UNSUPPORTED_MEDIA_TYPE",
                    detail="Office conversion is unavailable on this server.",
                )
            part_name = "file"
            writer_salt = os.urandom(16)
            return
        raise DocVaultError(
            "BAD_REQUEST",
            detail="Send one metadata field followed by one file field.",
        )

    def scan_pdf(data: bytes) -> None:
        nonlocal scan_tail
        combined = scan_tail + data
        if PDF_ACTIVE_CONTENT.search(combined):
            raise DocVaultError(
                "UNSUPPORTED_MEDIA_TYPE",
                detail="PDF scripts, launch actions, and embedded files are not accepted.",
            )
        scan_tail = combined[-64:]

    def start_writer(data: bytes, *, final: bool = False) -> bytes:
        nonlocal mime, writer
        if writer is not None:
            return data
        prefix.extend(data)
        sniffed = _sniff_mime(bytes(prefix))
        if sniffed is None and len(prefix) < 16 and not final:
            return b""
        suffix = Path(filename).suffix.lower()
        if suffix in {".doc", ".docx", ".odt"} and sniffed not in {
            "application/x-office-zip",
            "application/x-office-ole",
        }:
            sniffed = None
        if sniffed == "application/x-office-zip":
            sniffed = {
                ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                ".odt": "application/vnd.oasis.opendocument.text",
            }.get(suffix)
        elif sniffed == "application/x-office-ole":
            sniffed = "application/msword" if suffix == ".doc" else None
        if sniffed is None:
            raise DocVaultError(
                "UNSUPPORTED_MEDIA_TYPE",
                detail="Accepted file types are PDF, JPEG, PNG, DOC, DOCX, and ODT.",
            )
        mime = sniffed
        writer = BlobStreamWriter(
            temporary_path,
            max_plaintext_len=max_file_bytes,
            keys=keys,
            salt=writer_salt,
        )
        first = bytes(prefix)
        prefix.clear()
        file_hasher.update(first)
        if mime == "application/pdf":
            scan_pdf(first)
        writer.write(first)
        return b""

    def on_part_data(data: bytes, start: int, end: int) -> None:
        chunk = data[start:end]
        if part_name == "metadata":
            if len(metadata_bytes) + len(chunk) > MAX_METADATA_BYTES:
                raise DocVaultError("PAYLOAD_TOO_LARGE", detail="Metadata exceeds 64 KiB.")
            metadata_bytes.extend(chunk)
            return
        if part_name != "file":
            raise DocVaultError("BAD_REQUEST", detail="Unexpected multipart data.")
        if writer is None:
            remainder = start_writer(chunk)
            if remainder:
                raise AssertionError("MIME sniffer returned unconsumed bytes before writer setup.")
            return
        file_hasher.update(chunk)
        if mime == "application/pdf":
            scan_pdf(chunk)
        writer.write(chunk)

    def on_part_end() -> None:
        nonlocal metadata, address, plaintext_size, file_complete
        if part_name == "metadata":
            try:
                metadata = metadata_model.model_validate_json(bytes(metadata_bytes))
            except ValidationError as exc:
                raise _metadata_error(exc) from exc
            validate_metadata(metadata)
            return
        if part_name == "file":
            if writer is None:
                start_writer(b"", final=True)
            if writer is None:
                raise DocVaultError("UNSUPPORTED_MEDIA_TYPE")
            if mime == "application/pdf":
                scan_pdf(b"")
            address, plaintext_size = writer.finish()
            file_complete = True
            return
        raise DocVaultError("BAD_REQUEST", detail="Unexpected multipart part.")

    parser = MultipartParser(
        boundary,
        {
            "on_part_begin": on_part_begin,
            "on_header_field": on_header_field,
            "on_header_value": on_header_value,
            "on_header_end": on_header_end,
            "on_headers_finished": on_headers_finished,
            "on_part_data": on_part_data,
            "on_part_end": on_part_end,
        },
        max_size=max_file_bytes + MAX_MULTIPART_OVERHEAD,
    )
    try:
        async for chunk in request.stream():
            if parser.write(chunk) != len(chunk):
                raise DocVaultError("PAYLOAD_TOO_LARGE")
        parser.finalize()
    except MultipartParseError as exc:
        if writer is not None:
            writer.abort()
        raise DocVaultError("BAD_REQUEST", detail="The multipart upload is malformed.") from exc
    except BaseException:
        if writer is not None:
            writer.abort()
        raise

    if metadata is None or not file_complete or writer is None or writer_salt is None:
        if writer is not None:
            writer.abort()
        raise DocVaultError("BAD_REQUEST", detail="Both metadata and file parts are required.")
    return UploadResult(
        metadata=metadata,
        filename=filename,
        mime=mime,
        file_hash=file_hasher.digest(),
        address=address,
        salt=writer_salt,
        plaintext_size=plaintext_size,
        temporary_path=temporary_path,
    )


def _response(
    record: Document,
    version: DocumentVersion,
    title: str,
) -> DocumentResponse:
    return DocumentResponse(
        id=record.id,
        title=title,
        doc_type_id=record.doc_type_id,
        issue_date=record.issue_date,
        expiry_date=record.expiry_date,
        confidentiality=record.confidentiality,
        status=record.status,
        row_version=record.row_version,
        version=VersionResponse(
            id=version.id,
            version_no=version.version_no,
            plaintext_size=version.plaintext_size,
            mime=version.mime,
            derived_pdf=_derived_pdf_info(version),
        ),
    )


def _idempotency_lock_key(user_id: uuid.UUID, key: str) -> int:
    digest = hashlib.sha256(user_id.bytes + b"\x00" + key.encode("utf-8")).digest()[:8]
    return int.from_bytes(digest, byteorder="big", signed=True)


def _upload_request_hash[UploadModel: BaseModel](
    uploaded: UploadResult[UploadModel],
) -> bytes:
    return hashlib.sha256(
        canonical_json(
            {
                "metadata": uploaded.metadata.model_dump(mode="json"),
                "filename": uploaded.filename,
                "mime": uploaded.mime,
                "file_hash": uploaded.file_hash.hex(),
            }
        )
    ).digest()


def _cached_response[ResponseModel: BaseModel](
    session: OrmSession,
    actor_id: uuid.UUID,
    key: str,
    request_hash: bytes,
    *,
    endpoint: str,
    response_model: type[ResponseModel],
) -> ResponseModel | None:
    record = session.scalar(
        select(IdempotencyKey)
        .where(IdempotencyKey.user_id == actor_id, IdempotencyKey.key == key)
        .with_for_update()
    )
    if record is None:
        return None
    if record.endpoint != endpoint:
        raise DocVaultError("CONFLICT", detail="Idempotency-Key was used for another endpoint.")
    if record.expires_at <= datetime.now(UTC):
        session.delete(record)
        return None
    if record.request_hash != request_hash:
        raise DocVaultError(
            "CONFLICT",
            detail="Idempotency-Key was already used with a different request.",
        )
    if record.response_ref is None:
        raise DocVaultError("CONFLICT", detail="The idempotent request has no completed response.")
    return response_model.model_validate(record.response_ref)


def _set_document_headers(response: Response, body: DocumentResponse) -> None:
    response.headers["ETag"] = f'W/"{body.row_version}"'
    response.headers["Location"] = f"/api/v1/documents/{body.id}"


def _document_response(
    session: OrmSession,
    keys: VaultKeys,
    document: Document,
) -> DocumentResponse:
    version = session.get(DocumentVersion, document.current_version_id)
    if version is None:
        raise DocVaultError("BLOB_INVALID", detail="The document has no current version record.")
    title = decrypt_column(keys.meta_key, "documents", "title_enc", document.title_enc)
    if title is None:
        raise DocVaultError(
            "COLUMN_TAMPERED", detail="documents.title_enc did not contain a title."
        )
    return _response(document, version, title)


def _search_document_records(
    session: OrmSession,
    keys: VaultKeys,
    statement: Select[Document],
    query: str,
    limit: int,
) -> list[Document]:
    query_text = unicodedata.normalize("NFC", query).strip().casefold()
    matches: list[Document] = []
    offset = 0
    while len(matches) <= limit and offset < MAX_SEARCH_CANDIDATES:
        batch = list(session.scalars(statement.limit(100).offset(offset)))
        offset += len(batch)
        for record in batch:
            title = decrypt_column(keys.meta_key, "documents", "title_enc", record.title_enc)
            if title is None:
                raise DocVaultError(
                    "COLUMN_TAMPERED", detail="documents.title_enc did not contain a title."
                )
            if query_text in unicodedata.normalize("NFC", title).casefold():
                matches.append(record)
                if len(matches) > limit:
                    break
        if len(batch) < 100:
            break
    if (
        len(matches) <= limit
        and offset >= MAX_SEARCH_CANDIDATES
        and session.scalar(statement.limit(1).offset(offset)) is not None
    ):
        raise DocVaultError(
            "PAYLOAD_TOO_LARGE",
            detail="Search matched too many candidate documents; narrow the filters.",
        )
    return matches


def _if_match(value: str | None) -> int:
    if value is None:
        raise DocVaultError("PRECONDITION_REQUIRED")
    normalized = value.removeprefix("W/").strip()
    if len(normalized) < 3 or normalized[0] != '"' or normalized[-1] != '"':
        raise DocVaultError("BAD_REQUEST", detail="If-Match must contain an ETag.")
    try:
        version = int(normalized[1:-1])
    except ValueError as exc:
        raise DocVaultError("BAD_REQUEST", detail="If-Match must contain a numeric ETag.") from exc
    if version < 1:
        raise DocVaultError("BAD_REQUEST", detail="If-Match must be a positive version.")
    return version


def _lock_writable_document(
    session: OrmSession,
    actor: auth.AuthenticatedSession,
    document_id: uuid.UUID,
    if_match: str | None,
    source_ip: str | None,
) -> Document:
    expected_version = _if_match(if_match)
    document = session.execute(
        select(Document)
        .where(Document.id == document_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if document is None:
        acl.require_document(session, actor.user_id, document_id, acl.WRITE, source_ip=source_ip)
    document = acl.require_document(
        session, actor.user_id, document_id, acl.WRITE, source_ip=source_ip
    )
    if document.row_version != expected_version:
        raise DocVaultError("CONFLICT", detail="The document changed. Reload and retry.")
    return document


def _normalize_tag_name(name: str) -> str:
    normalized = unicodedata.normalize("NFC", name).strip().casefold()
    if (
        not normalized
        or len(normalized) > 100
        or any(unicodedata.category(char) == "Cc" for char in normalized)
    ):
        raise DocVaultError(
            "VALIDATION_FAILED",
            fields=[{"field": "name", "code": "invalid", "message": "Use 1-100 valid characters."}],
        )
    return normalized


def _get_or_create_tag(
    session: OrmSession,
    keys: VaultKeys,
    name: str,
    color: str | None = None,
) -> tuple[Tag, bool]:
    normalized = _normalize_tag_name(name)
    name_blind = blind_index(keys.bidx_key, "tag_name", normalized)
    tag = session.scalar(select(Tag).where(Tag.name_blind == name_blind))
    if tag is not None:
        if color is not None and tag.color != color:
            raise DocVaultError("CONFLICT", detail="The tag already exists with another color.")
        return tag, False
    tag = Tag(
        name_enc=encrypt_column(keys.meta_key, "tags", "name_enc", normalized) or b"",
        name_blind=name_blind,
        color=color,
    )
    session.add(tag)
    session.flush()
    return tag, True


def _tag_response(keys: VaultKeys, tag: Tag) -> TagResponse:
    name = decrypt_column(keys.meta_key, "tags", "name_enc", tag.name_enc)
    if name is None:
        raise DocVaultError("COLUMN_TAMPERED", detail="tags.name_enc did not contain a name.")
    return TagResponse(id=tag.id, name=name, color=tag.color, is_system=tag.is_system)


def _doc_type_response(keys: VaultKeys, doc_type: DocType) -> DocTypeResponse:
    name = decrypt_column(keys.meta_key, "doc_types", "name_enc", doc_type.name_enc)
    if name is None:
        raise DocVaultError("COLUMN_TAMPERED", detail="doc_types.name_enc did not contain a name.")
    purpose = decrypt_column(keys.meta_key, "doc_types", "purpose_enc", doc_type.purpose_enc)
    return DocTypeResponse(
        id=doc_type.id,
        code=doc_type.code,
        name=name,
        parent_id=doc_type.parent_id,
        default_confidentiality=doc_type.default_confidentiality,
        retention_months=doc_type.retention_months,
        requires_expiry=doc_type.requires_expiry,
        side=doc_type.side,
        purpose=purpose,
        is_system=doc_type.is_system,
        sort_order=doc_type.sort_order,
        row_version=doc_type.row_version,
    )


def _validate_doc_type_parent(
    session: OrmSession,
    parent_id: uuid.UUID | None,
    *,
    current_id: uuid.UUID | None = None,
) -> None:
    if parent_id is None:
        return
    parent = session.get(DocType, parent_id)
    if parent is None or parent.parent_id is not None or parent.id == current_id:
        raise DocVaultError(
            "VALIDATION_FAILED",
            fields=[
                {
                    "field": "parent_id",
                    "code": "invalid_parent",
                    "message": "A document type must be under a category.",
                }
            ],
        )


def _lock_doc_type_tree(session: OrmSession) -> None:
    session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": DOC_TYPE_TREE_LOCK})


def _apply_doc_type_changes(
    doc_type: DocType,
    keys: VaultKeys,
    changes: dict[str, object],
) -> None:
    for field_name, raw_value in changes.items():
        target_field = field_name
        stored_value: object
        if field_name == "name":
            if not isinstance(raw_value, str):
                raise DocVaultError("VALIDATION_FAILED", detail="The name cannot be null.")
            stored_value = encrypt_column(
                keys.meta_key,
                "doc_types",
                "name_enc",
                _normalize_doc_type_name(raw_value),
            )
            target_field = "name_enc"
        elif field_name == "purpose":
            if raw_value is not None and not isinstance(raw_value, str):
                raise DocVaultError("VALIDATION_FAILED", detail="Purpose must be text or null.")
            stored_value = encrypt_column(keys.meta_key, "doc_types", "purpose_enc", raw_value)
            target_field = "purpose_enc"
        elif field_name == "default_confidentiality" and raw_value is None:
            raise DocVaultError("VALIDATION_FAILED", detail="Confidentiality cannot be null.")
        else:
            stored_value = raw_value
        setattr(doc_type, target_field, stored_value)


def _normalize_doc_type_name(name: str) -> str:
    normalized = unicodedata.normalize("NFC", name).strip()
    if (
        not normalized
        or len(normalized) > 200
        or any(unicodedata.category(char) == "Cc" for char in normalized)
    ):
        raise DocVaultError(
            "VALIDATION_FAILED",
            fields=[{"field": "name", "code": "invalid", "message": "Use 1-200 valid characters."}],
        )
    return normalized


def _byte_range(value: str | None, size: int) -> tuple[int, int] | None:
    if value is None:
        return None
    match = re.fullmatch(r"bytes=(\d*)-(\d*)", value.strip(), flags=re.IGNORECASE)
    if match is None or size == 0:
        raise DocVaultError("RANGE_NOT_SATISFIABLE")
    first, last = match.groups()
    if not first and not last:
        raise DocVaultError("RANGE_NOT_SATISFIABLE")
    if len(first) > 20 or len(last) > 20:
        raise DocVaultError("RANGE_NOT_SATISFIABLE")
    if not first:
        suffix_length = int(last)
        if suffix_length == 0:
            raise DocVaultError("RANGE_NOT_SATISFIABLE")
        return max(0, size - suffix_length), size - 1
    start = int(first)
    end = int(last) if last else size - 1
    if start >= size or end < start:
        raise DocVaultError("RANGE_NOT_SATISFIABLE")
    return start, min(end, size - 1)


def _overwrite_unlink(path: Path) -> None:
    directory_fd: int | None = None
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise DocVaultError("BLOB_INVALID", detail="A blob could not be opened for purge.") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise DocVaultError("BLOB_INVALID", detail="A blob path is not a regular file.")
        offset = 0
        while offset < info.st_size:
            chunk = secrets.token_bytes(min(64 * 1024, info.st_size - offset))
            written = os.pwrite(descriptor, chunk, offset)
            if written <= 0:
                raise DocVaultError("BLOB_INVALID", detail="A blob could not be overwritten.")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        raise DocVaultError(
            "BLOB_INVALID", detail="A blob could not be flushed during purge."
        ) from exc
    finally:
        os.close(descriptor)
    try:
        path.unlink()
        directory_fd = os.open(path.parent, os.O_RDONLY)
        os.fsync(directory_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise DocVaultError("BLOB_INVALID", detail="A purged blob could not be unlinked.") from exc
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


@router.post("/documents", response_model=DocumentResponse, status_code=201)
async def upload_document(  # noqa: PLR0915
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> DocumentResponse:
    """Validate metadata before streaming the file directly into encrypted storage."""
    vault = _vault(request)
    keys = vault.keys
    engine = _engine(request)
    source_ip = _source_ip(request)
    with OrmSession(engine) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)
        if idempotency_key is None or not idempotency_key.strip() or len(idempotency_key) > 200:
            raise DocVaultError(
                "VALIDATION_FAILED",
                fields=[
                    {
                        "field": "Idempotency-Key",
                        "code": "required",
                        "message": "Provide a non-empty idempotency key of at most 200 characters.",
                    }
                ],
            )
    temporary_path = vault.paths.tmp / f"{uuid.uuid4().hex}.part"
    preflight_type_id: uuid.UUID | None = None
    preflight_confidentiality: ConfLevel | None = None

    def validate_metadata(metadata: UploadMetadata) -> None:
        nonlocal preflight_type_id, preflight_confidentiality
        with OrmSession(engine) as session, session.begin():
            preflight_type_id, preflight_confidentiality = _validate_metadata(
                session, actor, metadata, source_ip
            )

    uploaded: UploadResult[UploadMetadata] | None = None
    final_path: Path | None = None
    derived_path: Path | None = None
    try:
        office_converter = _office_converter(request)
        uploaded = await _stream_multipart(
            request,
            keys=keys,
            max_file_bytes=vault.manifest.max_file_bytes,
            temporary_path=temporary_path,
            metadata_model=UploadMetadata,
            validate_metadata=validate_metadata,
            office_converter_available=office_converter is not None,
        )
        derived_pdf = _validate_uploaded_content(
            uploaded,
            keys=keys,
            vault=vault,
            office_converter=office_converter,
        )
        derived_path = derived_pdf.path if derived_pdf is not None else None
        if preflight_type_id is None or preflight_confidentiality is None:
            raise DocVaultError("VALIDATION_FAILED", detail="Document metadata was not validated.")
        final_path = vault.paths.blob(uploaded.address)
        final_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        uploaded.temporary_path.replace(final_path)
        directory_fd = os.open(final_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

        with OrmSession(engine) as session, session.begin():
            session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_key)"),
                {"lock_key": _idempotency_lock_key(actor.user_id, idempotency_key)},
            )
            request_hash = _upload_request_hash(uploaded)
            cached = _cached_response(
                session,
                actor.user_id,
                idempotency_key,
                request_hash,
                endpoint="/api/v1/documents",
                response_model=DocumentResponse,
            )
            if cached is not None:
                final_path.unlink(missing_ok=True)
                if derived_path is not None:
                    derived_path.unlink(missing_ok=True)
                _set_document_headers(response, cached)
                return cached

            links = uploaded.metadata.entity_links
            document = Document(
                doc_type_id=preflight_type_id,
                title_enc=encrypt_column(
                    keys.meta_key, "documents", "title_enc", uploaded.metadata.title.strip()
                )
                or b"",
                title_blind=blind_index(
                    keys.bidx_key, "document_title", uploaded.metadata.title.strip()
                ),
                issue_date=uploaded.metadata.issue_date,
                expiry_date=uploaded.metadata.expiry_date,
                owner_id=actor.user_id,
                created_by=actor.user_id,
                updated_by=actor.user_id,
                acl_mode=uploaded.metadata.acl_mode,
                confidentiality=preflight_confidentiality,
                version_count=1,
            )
            session.add(document)
            session.flush()
            version = DocumentVersion(
                document_id=document.id,
                version_no=1,
                blob_addr=uploaded.address,
                blob_salt=uploaded.salt,
                plaintext_size=uploaded.plaintext_size,
                stored_size=final_path.stat().st_size,
                mime=uploaded.mime,
                derived_pdf_addr=derived_pdf.address if derived_pdf is not None else None,
                derived_pdf_salt=derived_pdf.salt if derived_pdf is not None else None,
                derived_pdf_pages=derived_pdf.page_count if derived_pdf is not None else None,
                derived_pdf_size=derived_pdf.plaintext_size if derived_pdf is not None else None,
                original_filename_enc=encrypt_column(
                    keys.meta_key,
                    "document_versions",
                    "original_filename_enc",
                    uploaded.filename,
                )
                or b"",
                uploaded_by=actor.user_id,
            )
            session.add(version)
            session.flush()
            document.current_version_id = version.id

            for link in links:
                session.add(
                    DocumentEntityLink(
                        document_id=document.id,
                        entity_id=link.entity_id,
                        link_role=link.link_role,
                    )
                )
            normalized_tags = [_normalize_tag_name(raw) for raw in uploaded.metadata.tags]
            if len(set(normalized_tags)) != len(normalized_tags):
                raise DocVaultError("VALIDATION_FAILED", detail="Tags must be unique.")
            for tag_name in normalized_tags:
                tag, _ = _get_or_create_tag(session, keys, tag_name)
                session.add(DocumentTag(document_id=document.id, tag_id=tag.id))

            append_event(
                session,
                action="document.create",
                object_type="document",
                object_id=document.id,
                actor_id=actor.user_id,
                source_ip=source_ip,
                detail={
                    "version_id": str(version.id),
                    "version_no": 1,
                    "mime": uploaded.mime,
                    "plaintext_size": uploaded.plaintext_size,
                },
            )
            result = _response(document, version, uploaded.metadata.title.strip())
            session.add(
                IdempotencyKey(
                    key=idempotency_key,
                    user_id=actor.user_id,
                    endpoint="/api/v1/documents",
                    request_hash=request_hash,
                    response_ref=result.model_dump(mode="json"),
                    expires_at=datetime.now(UTC) + timedelta(hours=24),
                )
            )
            _set_document_headers(response, result)
            return result
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        if final_path is not None:
            final_path.unlink(missing_ok=True)
        if derived_path is not None:
            derived_path.unlink(missing_ok=True)
        raise


@router.post(
    "/documents/{document_id}/versions",
    response_model=VersionResponse,
    status_code=201,
)
async def upload_document_version(  # noqa: PLR0915
    document_id: uuid.UUID,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> VersionResponse:
    vault = _vault(request)
    keys = vault.keys
    engine = _engine(request)
    source_ip = _source_ip(request)
    if idempotency_key is None or not idempotency_key.strip() or len(idempotency_key) > 200:
        raise DocVaultError(
            "VALIDATION_FAILED",
            fields=[
                {
                    "field": "Idempotency-Key",
                    "code": "required",
                    "message": "Provide a non-empty idempotency key of at most 200 characters.",
                }
            ],
        )
    with OrmSession(engine) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)

    def validate_metadata(_metadata: VersionUploadMetadata) -> None:
        with OrmSession(engine) as session, session.begin():
            acl.require_document(
                session,
                actor.user_id,
                document_id,
                acl.WRITE,
                source_ip=source_ip,
            )

    temporary_path = vault.paths.tmp / f"{uuid.uuid4().hex}.part"
    final_path: Path | None = None
    derived_path: Path | None = None
    try:
        office_converter = _office_converter(request)
        uploaded = await _stream_multipart(
            request,
            keys=keys,
            max_file_bytes=vault.manifest.max_file_bytes,
            temporary_path=temporary_path,
            metadata_model=VersionUploadMetadata,
            validate_metadata=validate_metadata,
            office_converter_available=office_converter is not None,
        )
        derived_pdf = _validate_uploaded_content(
            uploaded,
            keys=keys,
            vault=vault,
            office_converter=office_converter,
        )
        derived_path = derived_pdf.path if derived_pdf is not None else None
        final_path = vault.paths.blob(uploaded.address)
        final_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        uploaded.temporary_path.replace(final_path)
        directory_fd = os.open(final_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

        with OrmSession(engine) as session, session.begin():
            session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_key)"),
                {"lock_key": _idempotency_lock_key(actor.user_id, idempotency_key)},
            )
            request_hash = _upload_request_hash(uploaded)
            cached = _cached_response(
                session,
                actor.user_id,
                idempotency_key,
                request_hash,
                endpoint=f"/api/v1/documents/{document_id}/versions",
                response_model=VersionResponse,
            )
            if cached is not None:
                final_path.unlink(missing_ok=True)
                if derived_path is not None:
                    derived_path.unlink(missing_ok=True)
                return cached

            document = session.execute(
                select(Document)
                .where(Document.id == document_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            ).scalar_one_or_none()
            if document is None:
                acl.require_document(
                    session,
                    actor.user_id,
                    document_id,
                    acl.WRITE,
                    source_ip=source_ip,
                )
            document = acl.require_document(
                session,
                actor.user_id,
                document_id,
                acl.WRITE,
                source_ip=source_ip,
            )
            latest_version = session.scalar(
                select(func.max(DocumentVersion.version_no)).where(
                    DocumentVersion.document_id == document.id
                )
            )
            version = DocumentVersion(
                document_id=document.id,
                version_no=(latest_version or 0) + 1,
                blob_addr=uploaded.address,
                blob_salt=uploaded.salt,
                plaintext_size=uploaded.plaintext_size,
                stored_size=final_path.stat().st_size,
                mime=uploaded.mime,
                derived_pdf_addr=derived_pdf.address if derived_pdf is not None else None,
                derived_pdf_salt=derived_pdf.salt if derived_pdf is not None else None,
                derived_pdf_pages=derived_pdf.page_count if derived_pdf is not None else None,
                derived_pdf_size=derived_pdf.plaintext_size if derived_pdf is not None else None,
                original_filename_enc=encrypt_column(
                    keys.meta_key,
                    "document_versions",
                    "original_filename_enc",
                    uploaded.filename,
                )
                or b"",
                note_enc=encrypt_column(
                    keys.meta_key,
                    "document_versions",
                    "note_enc",
                    (uploaded.metadata.note or "").strip(),
                )
                if (uploaded.metadata.note or "").strip()
                else None,
                uploaded_by=actor.user_id,
            )
            session.add(version)
            session.flush()
            document.current_version_id = version.id
            document.row_version += 1
            document.updated_at = datetime.now(UTC)
            document.updated_by = actor.user_id
            append_event(
                session,
                action="document.version_upload",
                object_type="document",
                object_id=document.id,
                actor_id=actor.user_id,
                source_ip=source_ip,
                detail={
                    "version_id": str(version.id),
                    "version_no": version.version_no,
                    "mime": version.mime,
                    "plaintext_size": version.plaintext_size,
                },
            )
            result = VersionResponse(
                id=version.id,
                version_no=version.version_no,
                plaintext_size=version.plaintext_size,
                mime=version.mime,
                derived_pdf=_derived_pdf_info(version),
            )
            session.add(
                IdempotencyKey(
                    key=idempotency_key,
                    user_id=actor.user_id,
                    endpoint=f"/api/v1/documents/{document_id}/versions",
                    request_hash=request_hash,
                    response_ref=result.model_dump(mode="json"),
                    expires_at=datetime.now(UTC) + timedelta(hours=24),
                )
            )
            response.headers["ETag"] = f'W/"{document.row_version}"'
            response.headers["Location"] = (
                f"/api/v1/documents/{document_id}/versions/{version.version_no}"
            )
            return result
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        if final_path is not None:
            final_path.unlink(missing_ok=True)
        if derived_path is not None:
            derived_path.unlink(missing_ok=True)
        raise


@router.get("/doc-types", response_model=list[DocTypeCategory])
def list_doc_types(
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> list[DocTypeCategory]:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        auth.authenticate(session, keys, token)
        rows = list(
            session.scalars(select(DocType).order_by(DocType.sort_order, DocType.code, DocType.id))
        )
        categories = [row for row in rows if row.parent_id is None]
        types_by_parent: dict[uuid.UUID, list[DocType]] = {}
        for row in rows:
            if row.parent_id is not None:
                types_by_parent.setdefault(row.parent_id, []).append(row)
        return [
            DocTypeCategory(
                **_doc_type_response(keys, category).model_dump(),
                types=[
                    _doc_type_response(keys, child)
                    for child in types_by_parent.get(category.id, [])
                ],
            )
            for category in categories
        ]


@router.post("/doc-types", response_model=DocTypeResponse, status_code=201)
def create_doc_type(
    body: DocTypeInput,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> DocTypeResponse:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)
        if RoleName.ADMIN.value not in actor.roles:
            raise DocVaultError("FORBIDDEN", detail="Administrator role is required.")
        _lock_doc_type_tree(session)
        if session.scalar(select(DocType.id).where(DocType.code == body.code)) is not None:
            raise DocVaultError("CONFLICT", detail="A document type with this code already exists.")
        _validate_doc_type_parent(session, body.parent_id)
        normalized_name = _normalize_doc_type_name(body.name)
        doc_type = DocType(
            code=body.code,
            name_enc=encrypt_column(keys.meta_key, "doc_types", "name_enc", normalized_name) or b"",
            parent_id=body.parent_id,
            default_confidentiality=body.default_confidentiality,
            retention_months=body.retention_months,
            requires_expiry=body.requires_expiry,
            side=body.side,
            purpose_enc=encrypt_column(keys.meta_key, "doc_types", "purpose_enc", body.purpose),
            sort_order=body.sort_order,
        )
        session.add(doc_type)
        session.flush()
        append_event(
            session,
            action="doc_type.create",
            object_type="doc_type",
            object_id=doc_type.id,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
            detail={
                "code": doc_type.code,
                "parent_id": str(doc_type.parent_id) if doc_type.parent_id else None,
            },
        )
        response.headers["ETag"] = f'W/"{doc_type.row_version}"'
        response.headers["Location"] = f"/api/v1/doc-types/{doc_type.id}"
        return _doc_type_response(keys, doc_type)


@router.patch("/doc-types/{doc_type_id}", response_model=DocTypeResponse)
def update_doc_type(
    doc_type_id: uuid.UUID,
    body: DocTypePatch,
    request: Request,
    response: Response,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> DocTypeResponse:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)
        if RoleName.ADMIN.value not in actor.roles:
            raise DocVaultError("FORBIDDEN", detail="Administrator role is required.")
        _lock_doc_type_tree(session)
        expected_version = _if_match(if_match)
        doc_type = session.execute(
            select(DocType)
            .where(DocType.id == doc_type_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if doc_type is None:
            raise DocVaultError("NOT_FOUND")
        if doc_type.row_version != expected_version:
            raise DocVaultError("CONFLICT", detail="The document type changed. Reload and retry.")
        changes = body.model_dump(exclude_unset=True)
        if not changes:
            raise DocVaultError("VALIDATION_FAILED", detail="At least one field must be provided.")
        if "parent_id" in changes:
            _validate_doc_type_parent(session, changes["parent_id"], current_id=doc_type.id)
            if changes["parent_id"] is not None and doc_type.parent_id is None:
                has_children = session.scalar(
                    select(DocType.id).where(DocType.parent_id == doc_type.id).limit(1)
                )
                if has_children is not None:
                    raise DocVaultError(
                        "CONFLICT", detail="A category with document types cannot be nested."
                    )
        _apply_doc_type_changes(doc_type, keys, changes)
        doc_type.row_version += 1
        session.flush()
        append_event(
            session,
            action="doc_type.update",
            object_type="doc_type",
            object_id=doc_type.id,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
            detail={"fields": sorted(changes)},
        )
        response.headers["ETag"] = f'W/"{doc_type.row_version}"'
        return _doc_type_response(keys, doc_type)


@router.delete("/doc-types/{doc_type_id}", status_code=204)
def delete_doc_type(
    doc_type_id: uuid.UUID,
    request: Request,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)
        if RoleName.ADMIN.value not in actor.roles:
            raise DocVaultError("FORBIDDEN", detail="Administrator role is required.")
        _lock_doc_type_tree(session)
        expected_version = _if_match(if_match)
        doc_type = session.execute(
            select(DocType)
            .where(DocType.id == doc_type_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if doc_type is None:
            raise DocVaultError("NOT_FOUND")
        if doc_type.row_version != expected_version:
            raise DocVaultError("CONFLICT", detail="The document type changed. Reload and retry.")
        if doc_type.is_system:
            raise DocVaultError("CONFLICT", detail="System document types cannot be deleted.")
        if session.scalar(select(DocType.id).where(DocType.parent_id == doc_type.id).limit(1)):
            raise DocVaultError(
                "CONFLICT", detail="A category with document types cannot be deleted."
            )
        document_count = session.scalar(
            select(func.count()).select_from(Document).where(Document.doc_type_id == doc_type.id)
        )
        if document_count:
            raise DocVaultError(
                "CONFLICT",
                detail=f"This document type is assigned to {document_count} document(s).",
            )
        append_event(
            session,
            action="doc_type.delete",
            object_type="doc_type",
            object_id=doc_type.id,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
            detail={"code": doc_type.code},
        )
        session.delete(doc_type)
    return Response(status_code=204)


@router.get("/tags", response_model=list[TagResponse])
def list_tags(
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> list[TagResponse]:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        auth.authenticate(session, keys, token)
        tags = session.scalars(select(Tag))
        return sorted(
            (_tag_response(keys, tag) for tag in tags),
            key=lambda item: item.name.casefold(),
        )


@router.post("/tags", response_model=TagResponse, status_code=201)
def create_tag(
    body: TagInput,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> TagResponse:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)
        tag, created = _get_or_create_tag(session, keys, body.name, body.color)
        if created:
            append_event(
                session,
                action="tag.create",
                object_type="tag",
                object_id=tag.id,
                actor_id=actor.user_id,
                source_ip=_source_ip(request),
            )
        return _tag_response(keys, tag)


@router.delete("/tags/{tag_id}", status_code=204)
def delete_tag(
    tag_id: uuid.UUID,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)
        if RoleName.ADMIN.value not in actor.roles:
            raise DocVaultError("FORBIDDEN", detail="Administrator role is required.")
        tag = session.get(Tag, tag_id)
        if tag is None:
            raise DocVaultError("NOT_FOUND")
        if tag.is_system:
            raise DocVaultError("CONFLICT", detail="System tags cannot be deleted.")
        append_event(
            session,
            action="tag.delete",
            object_type="tag",
            object_id=tag.id,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
        )
        document_ids = set(
            session.scalars(select(DocumentTag.document_id).where(DocumentTag.tag_id == tag.id))
        )
        for document_id in document_ids:
            document = session.execute(
                select(Document)
                .where(Document.id == document_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            ).scalar_one_or_none()
            if document is None:
                continue
            document.row_version += 1
            document.updated_at = datetime.now(UTC)
            document.updated_by = actor.user_id
            append_event(
                session,
                action="document.tag_removed",
                object_type="document",
                object_id=document.id,
                actor_id=actor.user_id,
                source_ip=_source_ip(request),
                detail={"tag_id": str(tag.id), "reason": "tag_deleted"},
            )
        session.delete(tag)
    return Response(status_code=204)


@router.post("/documents/{document_id}/links", status_code=204)
def add_document_link(
    document_id: uuid.UUID,
    body: EntityLinkInput,
    request: Request,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    keys = _vault(request).keys
    source_ip = _source_ip(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)
        document = _lock_writable_document(session, actor, document_id, if_match, source_ip)
        acl.require_entity(session, actor.user_id, body.entity_id, acl.WRITE, source_ip=source_ip)
        link_key = (document_id, body.entity_id, body.link_role)
        if session.get(DocumentEntityLink, link_key) is None:
            session.add(
                DocumentEntityLink(
                    document_id=document_id,
                    entity_id=body.entity_id,
                    link_role=body.link_role,
                )
            )
            document.row_version += 1
            document.updated_at = datetime.now(UTC)
            document.updated_by = actor.user_id
            append_event(
                session,
                action="document.link_added",
                object_type="document",
                object_id=document_id,
                actor_id=actor.user_id,
                source_ip=source_ip,
                detail={"entity_id": str(body.entity_id), "link_role": body.link_role.value},
            )
        response = Response(status_code=204)
        response.headers["ETag"] = f'W/"{document.row_version}"'
        return response


@router.delete("/documents/{document_id}/links", status_code=204)
def remove_document_link(
    document_id: uuid.UUID,
    body: EntityLinkInput,
    request: Request,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    keys = _vault(request).keys
    source_ip = _source_ip(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)
        document = _lock_writable_document(session, actor, document_id, if_match, source_ip)
        link_key = (document_id, body.entity_id, body.link_role)
        link = session.get(DocumentEntityLink, link_key)
        if link is not None:
            session.delete(link)
            document.row_version += 1
            document.updated_at = datetime.now(UTC)
            document.updated_by = actor.user_id
            append_event(
                session,
                action="document.link_removed",
                object_type="document",
                object_id=document_id,
                actor_id=actor.user_id,
                source_ip=source_ip,
                detail={"entity_id": str(body.entity_id), "link_role": body.link_role.value},
            )
        response = Response(status_code=204)
        response.headers["ETag"] = f'W/"{document.row_version}"'
        return response


@router.post("/documents/{document_id}/tags", status_code=204)
def add_document_tag(
    document_id: uuid.UUID,
    body: TagInput,
    request: Request,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    keys = _vault(request).keys
    source_ip = _source_ip(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)
        document = _lock_writable_document(session, actor, document_id, if_match, source_ip)
        tag, _ = _get_or_create_tag(session, keys, body.name, body.color)
        tag_key = (document_id, tag.id)
        if session.get(DocumentTag, tag_key) is None:
            session.add(DocumentTag(document_id=document_id, tag_id=tag.id))
            document.row_version += 1
            document.updated_at = datetime.now(UTC)
            document.updated_by = actor.user_id
            append_event(
                session,
                action="document.tag_added",
                object_type="document",
                object_id=document_id,
                actor_id=actor.user_id,
                source_ip=source_ip,
                detail={"tag_id": str(tag.id)},
            )
        response = Response(status_code=204)
        response.headers["ETag"] = f'W/"{document.row_version}"'
        return response


@router.delete("/documents/{document_id}/tags", status_code=204)
def remove_document_tag(
    document_id: uuid.UUID,
    body: TagInput,
    request: Request,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    keys = _vault(request).keys
    source_ip = _source_ip(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)
        document = _lock_writable_document(session, actor, document_id, if_match, source_ip)
        name = _normalize_tag_name(body.name)
        tag_blind = blind_index(keys.bidx_key, "tag_name", name)
        tag = session.scalar(select(Tag).where(Tag.name_blind == tag_blind))
        if tag is None:
            raise DocVaultError("NOT_FOUND")
        tag_key = (document_id, tag.id)
        link = session.get(DocumentTag, tag_key)
        if link is not None:
            session.delete(link)
            document.row_version += 1
            document.updated_at = datetime.now(UTC)
            document.updated_by = actor.user_id
            append_event(
                session,
                action="document.tag_removed",
                object_type="document",
                object_id=document_id,
                actor_id=actor.user_id,
                source_ip=source_ip,
                detail={"tag_id": str(tag.id)},
            )
        response = Response(status_code=204)
        response.headers["ETag"] = f'W/"{document.row_version}"'
        return response


@router.get("/documents", response_model=DocumentListResponse)
def list_documents(  # noqa: PLR0912
    request: Request,
    q: Annotated[str | None, Query(max_length=128)] = None,
    entity_id: uuid.UUID | None = None,
    doc_type_id: uuid.UUID | None = None,
    category: Annotated[str | None, Query(max_length=128)] = None,
    confidentiality: ConfLevel | None = None,
    status: DocStatus | None = None,
    from_date: Annotated[date | None, Query(alias="from")] = None,
    to_date: Annotated[date | None, Query(alias="to")] = None,
    include_deleted: bool = False,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    cursor: uuid.UUID | None = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> DocumentListResponse:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        actor = auth.authenticate(session, keys, token)
        if include_deleted and RoleName.ADMIN.value not in actor.roles:
            raise DocVaultError(
                "FORBIDDEN", detail="Only administrators may include deleted documents."
            )
        statement = acl.visible_documents(
            session, actor.user_id, include_deleted=include_deleted
        ).order_by(Document.created_at.desc(), Document.id.desc())
        if entity_id is not None:
            linked = select(DocumentEntityLink.document_id).where(
                DocumentEntityLink.entity_id == entity_id
            )
            statement = statement.where(Document.id.in_(linked))
        if doc_type_id is not None:
            statement = statement.where(Document.doc_type_id == doc_type_id)
        if category is not None:
            category_id = select(DocType.id).where(
                DocType.code == category,
                DocType.parent_id.is_(None),
            )
            category_types = select(DocType.id).where(DocType.parent_id.in_(category_id))
            statement = statement.where(Document.doc_type_id.in_(category_types))
        if confidentiality is not None:
            statement = statement.where(Document.confidentiality == confidentiality)
        if status is not None:
            statement = statement.where(Document.status == status)
        if from_date is not None:
            statement = statement.where(Document.issue_date >= from_date)
        if to_date is not None:
            statement = statement.where(Document.issue_date <= to_date)
        if from_date is not None and to_date is not None and from_date > to_date:
            raise DocVaultError(
                "VALIDATION_FAILED",
                fields=[
                    {
                        "field": "from",
                        "code": "invalid_range",
                        "message": "The start date must not follow the end date.",
                    }
                ],
            )
        if cursor is not None:
            cursor_document = session.get(Document, cursor)
            if cursor_document is None:
                raise DocVaultError("BAD_REQUEST", detail="The pagination cursor is invalid.")
            statement = statement.where(
                (Document.created_at < cursor_document.created_at)
                | (
                    (Document.created_at == cursor_document.created_at)
                    & (Document.id < cursor_document.id)
                )
            )
        if q and q.strip():
            records = _search_document_records(session, keys, statement, q, limit)
        else:
            records = list(session.scalars(statement.limit(limit + 1)))
        page = records[:limit]
        next_cursor = str(page[-1].id) if len(records) > limit and page else None
        items = [_document_response(session, keys, record) for record in page]
    return DocumentListResponse(items=items, next_cursor=next_cursor)


@router.get("/documents/{document_id}", response_model=DocumentResponse)
def get_document(
    document_id: uuid.UUID,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> DocumentResponse:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        actor = auth.authenticate(session, keys, token)
        document = acl.require_document(
            session,
            actor.user_id,
            document_id,
            acl.VIEW,
            source_ip=_source_ip(request),
        )
        result = _document_response(session, keys, document)
        response.headers["ETag"] = f'W/"{document.row_version}"'
        return result


@router.patch("/documents/{document_id}", response_model=DocumentResponse)
def patch_document(  # noqa: PLR0912, PLR0915
    document_id: uuid.UUID,
    body: DocumentPatch,
    request: Request,
    response: Response,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> DocumentResponse:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)
        expected_version = _if_match(if_match)
        document = session.execute(
            select(Document)
            .where(Document.id == document_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if document is None:
            acl.require_document(
                session,
                actor.user_id,
                document_id,
                acl.WRITE,
                source_ip=_source_ip(request),
            )
        document = acl.require_document(
            session,
            actor.user_id,
            document_id,
            acl.WRITE,
            source_ip=_source_ip(request),
        )
        if document.row_version != expected_version:
            raise DocVaultError("CONFLICT", detail="The document changed. Reload and retry.")
        changes = body.model_dump(exclude_unset=True)
        if not changes:
            raise DocVaultError("VALIDATION_FAILED", detail="PATCH must change at least one field.")
        changed: list[str] = []
        if "title" in changes:
            title = changes["title"]
            if not isinstance(title, str):
                raise DocVaultError("VALIDATION_FAILED", detail="title cannot be null.")
            normalized_title = title.strip()
            if not normalized_title or len(normalized_title) > 300:
                raise DocVaultError(
                    "VALIDATION_FAILED",
                    fields=[
                        {
                            "field": "title",
                            "code": "invalid_length",
                            "message": "Use 1-300 characters.",
                        }
                    ],
                )
            document.title_enc = (
                encrypt_column(keys.meta_key, "documents", "title_enc", normalized_title) or b""
            )
            document.title_blind = blind_index(keys.bidx_key, "document_title", normalized_title)
            changed.append("title")
        if "issue_date" in changes:
            issue_date = changes["issue_date"]
            if issue_date is not None and not isinstance(issue_date, date):
                raise DocVaultError("VALIDATION_FAILED", detail="issue_date is invalid.")
            document.issue_date = issue_date
            changed.append("issue_date")
        if "expiry_date" in changes:
            expiry_date = changes["expiry_date"]
            if expiry_date is not None and not isinstance(expiry_date, date):
                raise DocVaultError("VALIDATION_FAILED", detail="expiry_date is invalid.")
            document.expiry_date = expiry_date
            changed.append("expiry_date")
        if (
            document.issue_date is not None
            and document.expiry_date is not None
            and document.expiry_date < document.issue_date
        ):
            raise DocVaultError(
                "VALIDATION_FAILED", detail="expiry_date must not precede issue_date."
            )
        if "confidentiality" in changes:
            confidentiality = changes["confidentiality"]
            if not isinstance(confidentiality, ConfLevel):
                raise DocVaultError("VALIDATION_FAILED", detail="confidentiality cannot be null.")
            levels = {
                ConfLevel.NORMAL: 0,
                ConfLevel.SENSITIVE: 1,
                ConfLevel.RESTRICTED: 2,
            }
            if (
                levels[confidentiality] < levels[document.confidentiality]
                and RoleName.ADMIN.value not in actor.roles
            ):
                raise DocVaultError(
                    "VALIDATION_FAILED",
                    detail="Only an administrator may lower confidentiality.",
                )
            document.confidentiality = confidentiality
            changed.append("confidentiality")
        document.row_version += 1
        document.updated_at = datetime.now(UTC)
        document.updated_by = actor.user_id
        session.flush()
        append_event(
            session,
            action="document.update",
            object_type="document",
            object_id=document.id,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
            detail={"fields": changed},
        )
        result = _document_response(session, keys, document)
        response.headers["ETag"] = f'W/"{document.row_version}"'
        return result


@router.delete("/documents/{document_id}", status_code=204)
def delete_document(
    document_id: uuid.UUID,
    request: Request,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)
        expected_version = _if_match(if_match)
        document = session.execute(
            select(Document)
            .where(Document.id == document_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if document is None:
            acl.require_document(
                session,
                actor.user_id,
                document_id,
                acl.DELETE,
                source_ip=_source_ip(request),
            )
        document = acl.require_document(
            session,
            actor.user_id,
            document_id,
            acl.DELETE,
            source_ip=_source_ip(request),
        )
        if document.row_version != expected_version:
            raise DocVaultError("CONFLICT", detail="The document changed. Reload and retry.")
        now = datetime.now(UTC)
        document.status = DocStatus.DELETED
        document.deleted_at = now
        document.deleted_by = actor.user_id
        document.purge_after = now.date() + timedelta(days=30)
        document.updated_at = now
        document.updated_by = actor.user_id
        document.row_version += 1
        append_event(
            session,
            action="document.delete",
            object_type="document",
            object_id=document.id,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
        )
    return Response(status_code=204)


@router.post("/documents/{document_id}/restore", response_model=DocumentResponse)
def restore_document(
    document_id: uuid.UUID,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> DocumentResponse:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)
        document = session.execute(
            select(Document)
            .where(Document.id == document_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if document is None:
            acl.require_document(
                session,
                actor.user_id,
                document_id,
                acl.DELETE,
                source_ip=_source_ip(request),
                include_deleted=True,
            )
        document = acl.require_document(
            session,
            actor.user_id,
            document_id,
            acl.DELETE,
            source_ip=_source_ip(request),
            include_deleted=True,
        )
        if document.deleted_at is None:
            raise DocVaultError("CONFLICT", detail="The document is not deleted.")
        document.deleted_at = None
        document.deleted_by = None
        document.purge_after = None
        document.status = DocStatus.ACTIVE
        document.updated_at = datetime.now(UTC)
        document.updated_by = actor.user_id
        document.row_version += 1
        append_event(
            session,
            action="document.restore",
            object_type="document",
            object_id=document.id,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
        )
        result = _document_response(session, keys, document)
        response.headers["ETag"] = f'W/"{document.row_version}"'
        return result


@router.post("/documents/{document_id}/purge", status_code=204)
def purge_document(
    document_id: uuid.UUID,
    body: PurgeRequest,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    vault = _vault(request)
    keys = vault.keys
    reason = body.reason.strip()
    if len(reason) < 10:
        raise DocVaultError(
            "VALIDATION_FAILED",
            fields=[
                {
                    "field": "reason",
                    "code": "too_short",
                    "message": "Provide a purge reason of at least 10 characters.",
                }
            ],
        )
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)
        if RoleName.ADMIN.value not in actor.roles:
            raise DocVaultError("FORBIDDEN", detail="Only administrators may purge documents.")
        document = session.execute(
            select(Document)
            .where(Document.id == document_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if document is None:
            raise DocVaultError("NOT_FOUND")
        if document.deleted_at is None:
            raise DocVaultError("CONFLICT", detail="Soft-delete the document before purging it.")
        if document.purged_at is not None:
            raise DocVaultError("CONFLICT", detail="The document has already been purged.")
        if document.legal_hold:
            raise DocVaultError("CONFLICT", detail="A legal hold prevents this purge.")
        today = datetime.now(UTC).date()
        if document.purge_after is not None and document.purge_after > today:
            raise DocVaultError(
                "CONFLICT",
                detail=f"The document cannot be purged before {document.purge_after.isoformat()}.",
            )

        versions = list(
            session.scalars(
                select(DocumentVersion)
                .where(DocumentVersion.document_id == document.id)
                .order_by(DocumentVersion.version_no)
                .with_for_update()
            )
        )
        version_ids = [version.id for version in versions]
        renditions = (
            list(session.scalars(select(Rendition).where(Rendition.version_id.in_(version_ids))))
            if version_ids
            else []
        )
        addresses = (
            {version.blob_addr for version in versions}
            | {version.derived_pdf_addr for version in versions if version.derived_pdf_addr}
            | {rendition.blob_addr for rendition in renditions}
        )
        for address in sorted(addresses):
            _overwrite_unlink(vault.paths.blob(address))

        now = datetime.now(UTC)
        for version in versions:
            version.purged_at = now
        if version_ids:
            session.execute(delete(Rendition).where(Rendition.version_id.in_(version_ids)))
            session.execute(
                delete(VersionRenderSettings).where(
                    VersionRenderSettings.version_id.in_(version_ids)
                )
            )
            session.execute(
                delete(DownloadTicket).where(DownloadTicket.version_id.in_(version_ids))
            )
        document.purged_at = now
        document.row_version += 1
        document.updated_at = now
        document.updated_by = actor.user_id
        append_event(
            session,
            action="document.purge",
            object_type="document",
            object_id=document.id,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
            detail={
                "reason": reason,
                "version_count": len(versions),
                "blob_count": len(addresses),
            },
        )
    return Response(status_code=204)


@router.get("/documents/{document_id}/versions", response_model=list[VersionResponse])
def list_versions(
    document_id: uuid.UUID,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> list[VersionResponse]:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        actor = auth.authenticate(session, keys, token)
        acl.require_document(
            session,
            actor.user_id,
            document_id,
            acl.VIEW,
            source_ip=_source_ip(request),
        )
        versions = session.scalars(
            select(DocumentVersion)
            .where(DocumentVersion.document_id == document_id)
            .order_by(DocumentVersion.version_no)
        )
        return [
            VersionResponse(
                id=version.id,
                version_no=version.version_no,
                plaintext_size=version.plaintext_size,
                mime=version.mime,
                derived_pdf=_derived_pdf_info(version),
            )
            for version in versions
        ]


@router.get(
    "/documents/{document_id}/versions/{version_no}",
    response_model=VersionResponse,
)
def get_version(
    document_id: uuid.UUID,
    version_no: int,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> VersionResponse:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        actor = auth.authenticate(session, keys, token)
        document = acl.require_document(
            session,
            actor.user_id,
            document_id,
            acl.VIEW,
            source_ip=_source_ip(request),
        )
        version = session.scalar(
            select(DocumentVersion).where(
                DocumentVersion.document_id == document.id,
                DocumentVersion.version_no == version_no,
            )
        )
        if version is None:
            raise DocVaultError("NOT_FOUND")
        return VersionResponse(
            id=version.id,
            version_no=version.version_no,
            plaintext_size=version.plaintext_size,
            mime=version.mime,
            derived_pdf=_derived_pdf_info(version),
        )


@router.post(
    "/documents/{document_id}/versions/{version_no}/download-ticket",
    response_model=DownloadTicketResponse,
)
def create_download_ticket(
    document_id: uuid.UUID,
    version_no: int,
    request: Request,
    body: DownloadTicketRequest | None = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> DownloadTicketResponse:
    keys = _vault(request).keys
    source_ip = _source_ip(request)
    if source_ip is None:
        raise DocVaultError("BAD_REQUEST", detail="The request has no source address.")
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _authenticate(session, keys, token, csrf)
        document = acl.require_document(
            session,
            actor.user_id,
            document_id,
            acl.READ,
            source_ip=source_ip,
            break_glass_reason=body.break_glass_reason if body else None,
        )
        version = session.scalar(
            select(DocumentVersion).where(
                DocumentVersion.document_id == document.id,
                DocumentVersion.version_no == version_no,
            )
        )
        if version is None:
            raise DocVaultError("NOT_FOUND")
        raw_token = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + timedelta(seconds=60)
        session.add(
            DownloadTicket(
                token_hash=hashlib.sha256(raw_token.encode("ascii")).digest(),
                version_id=version.id,
                user_id=actor.user_id,
                expires_at=expires_at,
                source_ip=source_ip,
            )
        )
        filename = decrypt_column(
            keys.meta_key,
            "document_versions",
            "original_filename_enc",
            version.original_filename_enc,
        )
        if filename is None:
            raise DocVaultError("COLUMN_TAMPERED", detail="The stored filename is invalid.")
        append_event(
            session,
            action="document.download_ticket",
            object_type="document",
            object_id=document.id,
            actor_id=actor.user_id,
            source_ip=source_ip,
            detail={"version_id": str(version.id)},
        )
        return DownloadTicketResponse(
            url=f"/api/v1/downloads/{raw_token}",
            expires_at=expires_at,
            filename=filename,
        )


@router.get("/downloads/{ticket_token}")
def redeem_download_ticket(
    ticket_token: str,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    break_glass_reason: Annotated[str | None, Header(alias="X-Break-Glass-Reason")] = None,
    range_header: Annotated[str | None, Header(alias="Range")] = None,
) -> Response:
    keys = _vault(request).keys
    source_ip = _source_ip(request)
    if source_ip is None:
        raise DocVaultError("GONE")
    ticket_hash = hashlib.sha256(ticket_token.encode("utf-8")).digest()
    with OrmSession(_engine(request)) as session, session.begin():
        actor = auth.authenticate(session, keys, token)
        ticket = session.scalar(
            select(DownloadTicket).where(DownloadTicket.token_hash == ticket_hash).with_for_update()
        )
        now = datetime.now(UTC)
        if (
            ticket is None
            or ticket.rendition_id is not None
            or ticket.used_at is not None
            or ticket.expires_at <= now
            or ticket.user_id != actor.user_id
            or str(ticket.source_ip) != source_ip
        ):
            raise DocVaultError("GONE")
        version = session.get(DocumentVersion, ticket.version_id)
        if version is None:
            raise DocVaultError("GONE")
        document = acl.require_document(
            session,
            actor.user_id,
            version.document_id,
            acl.READ,
            source_ip=source_ip,
            break_glass_reason=break_glass_reason,
        )
        blob_path = _vault(request).paths.blob(version.blob_addr)
        plaintext = decrypt_blob(
            read_blob_file(blob_path),
            keys,
            salt=version.blob_salt,
            expected_address=version.blob_addr,
        ).plaintext
        try:
            requested_range = _byte_range(range_header, len(plaintext))
        except DocVaultError as exc:
            if exc.code != "RANGE_NOT_SATISFIABLE":
                raise
            return Response(
                status_code=416,
                headers={"Content-Range": f"bytes */{len(plaintext)}", "Cache-Control": "no-store"},
            )
        filename = decrypt_column(
            keys.meta_key,
            "document_versions",
            "original_filename_enc",
            version.original_filename_enc,
        )
        if filename is None:
            raise DocVaultError("COLUMN_TAMPERED", detail="The stored filename is invalid.")
        ticket.used_at = now
        append_event(
            session,
            action="document.download",
            object_type="document",
            object_id=document.id,
            actor_id=actor.user_id,
            source_ip=source_ip,
            detail={
                "version_id": str(version.id),
                "size": version.plaintext_size,
            },
        )
        mime = version.mime
    ascii_filename = re.sub(r"[^A-Za-z0-9._-]", "_", filename)
    status_code = 200
    content = plaintext
    headers = {
        "Cache-Control": "no-store",
        "Content-Disposition": (
            f'attachment; filename="{ascii_filename}"; '
            f"filename*=UTF-8''{quote(filename, safe='')}"
        ),
        "Accept-Ranges": "bytes",
    }
    if requested_range is not None:
        start, end = requested_range
        content = plaintext[start : end + 1]
        status_code = 206
        headers["Content-Range"] = f"bytes {start}-{end}/{len(plaintext)}"
    return Response(
        content=content,
        status_code=status_code,
        media_type=mime,
        headers=headers,
    )
