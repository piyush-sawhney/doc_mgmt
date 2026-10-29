"""ACL-gated in-memory print-job composition."""

from __future__ import annotations

import math
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Cookie, Header, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as OrmSession

from app.api.documents import _source_ip, _vault
from app.api.render import _saved_recipe
from app.core.errors import DocVaultError
from app.crypto.keys import VaultKeys
from app.db.enums import PrintStatus, RoleName
from app.db.models.documents import DocumentVersion
from app.db.models.operations import PrintItem, PrintJob
from app.render.worker_client import compose_pdf, inspect_pdf
from app.services import acl, auth
from app.services.audit import append_event
from app.vault.blobs import decrypt_blob, read_blob_file

router = APIRouter(prefix="/api/v1", tags=["printing"])
MAX_ITEMS = 100
MAX_PAGES = 500
MAX_SOURCE_BYTES = 32 * 1024 * 1024
PAGE_RANGE = re.compile(r"([1-9]\d*)(?:-([1-9]\d*))?\Z")


@dataclass(frozen=True, slots=True)
class PrintSource:
    data: bytes
    mime: str
    page_count: int
    recipe_hash: str
    recipe: dict[str, Any]


@dataclass(frozen=True, slots=True)
class PlannedItem:
    version_id: uuid.UUID
    document_id: uuid.UUID
    source: PrintSource
    ranges: tuple[tuple[int, int], ...]


class PrintLayout(BaseModel):
    model_config = ConfigDict(extra="forbid")

    paper: Literal["A4", "Letter", "Legal", "A5", "A3"] = "A4"
    orientation: Literal["portrait", "landscape"] = "portrait"
    cells_per_side: Literal[1, 2, 4, 6, 9] = 1
    duplex: bool = False
    flip_edge: Literal["long", "short"] | None = None
    margin_mm: int = Field(default=5, ge=0, le=50)
    gutter_mm: int = Field(default=4, ge=0, le=50)
    fit_mode: Literal["contain", "fill"] = "contain"

    @model_validator(mode="after")
    def validate_duplex(self) -> PrintLayout:
        if self.duplex != (self.flip_edge is not None):
            raise ValueError("flip_edge must be set exactly when duplex is enabled.")
        return self


class PrintItemRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version_id: uuid.UUID
    pages: str = Field(default="all", min_length=1, max_length=512)


class PrintRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    layout: PrintLayout = Field(default_factory=PrintLayout)
    items: list[PrintItemRequest] = Field(min_length=1, max_length=MAX_ITEMS)


class PrintItemResponse(BaseModel):
    version_id: uuid.UUID
    document_id: uuid.UUID
    pages: str
    recipe_hash: str


class PrintJobResponse(BaseModel):
    id: uuid.UUID
    created_at: datetime
    completed_at: datetime | None
    status: PrintStatus
    item_count: int
    page_count: int
    sheet_count: int
    layout: PrintLayout
    items: list[PrintItemResponse]


def _engine(request: Request) -> Engine:
    engine = getattr(request.app.state, "db_engine", None)
    if not isinstance(engine, Engine):
        raise DocVaultError("DB_UNAVAILABLE", detail="The database is not configured.")
    return engine


def recover_interrupted_print_jobs(engine: Engine) -> int:
    """Mark jobs left by a process crash as failed and append their terminal audit events."""
    recovered = 0
    with OrmSession(engine) as session, session.begin():
        jobs = list(
            session.scalars(
                select(PrintJob).where(PrintJob.status == PrintStatus.INTERRUPTED).with_for_update()
            )
        )
        for job in jobs:
            items = session.scalars(
                select(PrintItem)
                .where(PrintItem.print_job_id == job.id)
                .order_by(PrintItem.position)
            )
            job.status = PrintStatus.FAILED
            job.completed_at = datetime.now(UTC)
            append_event(
                session,
                action="print_job.create",
                object_type="print_job",
                object_id=job.id,
                actor_id=job.requested_by,
                source_ip=str(job.source_ip),
                outcome="error",
                detail={
                    "status": "failed",
                    "error_code": "process_interrupted",
                    "item_count": job.item_count,
                    "page_count": job.page_count,
                    "sheet_count": job.sheet_count,
                    "layout": _stored_layout(job).model_dump(mode="json"),
                    "items": [
                        {
                            "document_id": str(item.document_id),
                            "version_id": str(item.version_id),
                            "ranges": [_format_range(item.page_from, item.page_to)],
                            "recipe_hash": item.recipe_hash,
                        }
                        for item in items
                    ],
                },
            )
            recovered += 1
    return recovered


def _stored_layout(job: PrintJob) -> PrintLayout:
    return PrintLayout(
        paper=job.paper,
        orientation=job.orientation,
        cells_per_side=job.cells_per_side,
        duplex=job.duplex,
        flip_edge=job.flip_edge,
        margin_mm=job.margin_mm,
        gutter_mm=job.gutter_mm,
        fit_mode=job.fit_mode,
    )


def _parse_ranges(value: str, page_count: int, item_index: int) -> tuple[tuple[int, int], ...]:
    if value == "all":
        return ((1, page_count),)
    ranges: list[tuple[int, int]] = []
    for segment in value.split(","):
        match = PAGE_RANGE.fullmatch(segment.strip())
        if match is None:
            raise DocVaultError(
                "VALIDATION_FAILED",
                fields=[
                    {
                        "field": f"items.{item_index}.pages",
                        "code": "invalid_range",
                        "message": "Use 'all' or comma-separated page numbers and ranges.",
                    }
                ],
            )
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if end < start or end > page_count:
            raise DocVaultError(
                "VALIDATION_FAILED",
                fields=[
                    {
                        "field": f"items.{item_index}.pages",
                        "code": "out_of_bounds",
                        "message": f"Page ranges must be between 1 and {page_count}.",
                    }
                ],
            )
        ranges.append((start, end))
    return tuple(ranges)


def _format_range(start: int, end: int) -> str:
    return str(start) if start == end else f"{start}-{end}"


def _print_audit_detail(
    body: PrintRequest,
    plans: list[PlannedItem],
    *,
    page_count: int,
    sheet_count: int,
    status: str,
    error_code: str | None = None,
) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "status": status,
        "item_count": len(plans),
        "page_count": page_count,
        "sheet_count": sheet_count,
        "layout": body.layout.model_dump(mode="json"),
        "items": [
            {
                "document_id": str(plan.document_id),
                "version_id": str(plan.version_id),
                "ranges": [_format_range(start, end) for start, end in plan.ranges],
                "recipe_hash": plan.source.recipe_hash,
            }
            for plan in plans
        ],
    }
    if error_code is not None:
        detail["error_code"] = error_code
    return detail


def _source_for_version(
    request: Request,
    keys: VaultKeys,
    version: DocumentVersion,
) -> tuple[bytes, str, int]:
    address = version.derived_pdf_addr or version.blob_addr
    salt = version.derived_pdf_salt or version.blob_salt
    mime = "application/pdf" if version.derived_pdf_addr else version.mime
    plaintext = decrypt_blob(
        read_blob_file(_vault(request).paths.blob(address)),
        keys,
        salt=salt,
        expected_address=address,
    ).plaintext
    page_count = int(inspect_pdf(plaintext)["page_count"]) if mime == "application/pdf" else 1
    return plaintext, mime, page_count


def _record_failure(
    request: Request,
    *,
    body: PrintRequest,
    job_id: uuid.UUID,
    actor_id: uuid.UUID,
    source_ip: str,
    plans: list[PlannedItem],
    page_count: int,
    sheet_count: int,
    error_code: str,
) -> None:
    with OrmSession(_engine(request)) as session, session.begin():
        job = session.execute(
            select(PrintJob).where(PrintJob.id == job_id).with_for_update()
        ).scalar_one()
        job.status = PrintStatus.FAILED
        job.completed_at = datetime.now(UTC)
        append_event(
            session,
            action="print_job.create",
            object_type="print_job",
            object_id=job_id,
            actor_id=actor_id,
            source_ip=source_ip,
            outcome="error",
            detail=_print_audit_detail(
                body,
                plans,
                page_count=page_count,
                sheet_count=sheet_count,
                status="failed",
                error_code=error_code,
            ),
        )


def _job_response(session: OrmSession, job: PrintJob) -> PrintJobResponse:
    items = session.scalars(
        select(PrintItem).where(PrintItem.print_job_id == job.id).order_by(PrintItem.position)
    )
    return PrintJobResponse(
        id=job.id,
        created_at=job.created_at,
        completed_at=job.completed_at,
        status=job.status,
        item_count=job.item_count,
        page_count=job.page_count,
        sheet_count=job.sheet_count,
        layout=_stored_layout(job),
        items=[
            PrintItemResponse(
                version_id=item.version_id,
                document_id=item.document_id,
                pages=_format_range(item.page_from, item.page_to),
                recipe_hash=item.recipe_hash,
            )
            for item in items
        ],
    )


def _can_view_job(
    session: OrmSession,
    job: PrintJob,
    actor: auth.AuthenticatedSession,
    source_ip: str | None,
) -> bool:
    if RoleName.ADMIN.value in actor.roles:
        return True
    document_ids = session.scalars(
        select(PrintItem.document_id).where(PrintItem.print_job_id == job.id).distinct()
    )
    try:
        for document_id in document_ids:
            acl.require_document(
                session,
                actor.user_id,
                document_id,
                acl.VIEW,
                source_ip=source_ip,
            )
    except DocVaultError as exc:
        if exc.code == "NOT_FOUND":
            return False
        raise
    return True


def _plan_print_job(
    body: PrintRequest,
    request: Request,
    keys: VaultKeys,
    token: str | None,
    csrf: str | None,
) -> tuple[uuid.UUID, list[PlannedItem], int]:
    source_ip = _source_ip(request)
    if source_ip is None:
        raise DocVaultError("BAD_REQUEST", detail="The request has no source address.")
    plans: list[PlannedItem] = []
    page_count = 0
    total_source_bytes = 0
    source_cache: dict[uuid.UUID, PrintSource] = {}
    with OrmSession(_engine(request)) as session, session.begin():
        actor = auth.authenticate(session, keys, token)
        auth.verify_csrf(session, token, csrf)
        for item_index, item in enumerate(body.items):
            version = session.get(DocumentVersion, item.version_id)
            if version is None or version.purged_at is not None:
                raise DocVaultError("NOT_FOUND")
            document = acl.require_document(
                session,
                actor.user_id,
                version.document_id,
                acl.PRINT,
                source_ip=source_ip,
            )
            cached_source = source_cache.get(version.id)
            if cached_source is None:
                data, mime, count = _source_for_version(request, keys, version)
                total_source_bytes += len(data)
                if total_source_bytes > MAX_SOURCE_BYTES:
                    raise DocVaultError(
                        "PAYLOAD_TOO_LARGE",
                        detail="Print sources exceed the 32 MiB composition limit.",
                    )
                recipe_hash, recipe = _saved_recipe(session, keys, version.id)
                cached_source = PrintSource(
                    data=data,
                    mime=mime,
                    page_count=count,
                    recipe_hash=recipe_hash,
                    recipe=recipe,
                )
                source_cache[version.id] = cached_source
            ranges = _parse_ranges(item.pages, cached_source.page_count, item_index)
            selected = sum(end - start + 1 for start, end in ranges)
            page_count += selected
            if page_count > MAX_PAGES:
                raise DocVaultError(
                    "VALIDATION_FAILED",
                    fields=[
                        {
                            "field": f"items.{item_index}.pages",
                            "code": "too_many_pages",
                            "message": f"A print job may contain at most {MAX_PAGES} pages.",
                        }
                    ],
                )
            plans.append(PlannedItem(version.id, document.id, cached_source, ranges))
        actor_id = actor.user_id
    return actor_id, plans, page_count


def _persist_print_job(
    body: PrintRequest,
    request: Request,
    keys: VaultKeys,
    actor_id: uuid.UUID,
    source_ip: str,
    job_id: uuid.UUID,
    plans: list[PlannedItem],
    page_count: int,
    token: str | None,
    csrf: str | None,
) -> int:
    side_count = math.ceil(page_count / body.layout.cells_per_side)
    sheet_count = math.ceil(side_count / 2) if body.layout.duplex else side_count
    with OrmSession(_engine(request)) as session, session.begin():
        actor = auth.authenticate(session, keys, token)
        auth.verify_csrf(session, token, csrf)
        if actor.user_id != actor_id:
            raise DocVaultError("FORBIDDEN")
        for plan in plans:
            acl.require_document(
                session,
                actor.user_id,
                plan.document_id,
                acl.PRINT,
                source_ip=source_ip,
            )
        job = PrintJob(
            id=job_id,
            requested_by=actor_id,
            paper=body.layout.paper,
            orientation=body.layout.orientation,
            cells_per_side=body.layout.cells_per_side,
            duplex=body.layout.duplex,
            flip_edge=body.layout.flip_edge,
            margin_mm=body.layout.margin_mm,
            gutter_mm=body.layout.gutter_mm,
            fit_mode=body.layout.fit_mode,
            item_count=len(plans),
            page_count=page_count,
            sheet_count=sheet_count,
            status=PrintStatus.INTERRUPTED,
            source_ip=source_ip,
        )
        session.add(job)
        session.flush()
        position = 0
        for plan in plans:
            for start, end in plan.ranges:
                session.add(
                    PrintItem(
                        print_job_id=job.id,
                        position=position,
                        version_id=plan.version_id,
                        document_id=plan.document_id,
                        page_from=start,
                        page_to=end,
                        recipe_hash=plan.source.recipe_hash,
                    )
                )
                position += 1
    return sheet_count


def _compose_and_finalize(
    body: PrintRequest,
    request: Request,
    keys: VaultKeys,
    token: str | None,
    csrf: str | None,
    actor_id: uuid.UUID,
    source_ip: str,
    job_id: uuid.UUID,
    plans: list[PlannedItem],
    page_count: int,
    sheet_count: int,
) -> Response:
    composition_pages: list[dict[str, Any]] = []
    for plan in plans:
        for start, end in plan.ranges:
            composition_pages.extend(
                {
                    "data": plan.source.data,
                    "mime": plan.source.mime,
                    "page": page,
                    "recipe": plan.source.recipe,
                }
                for page in range(start, end + 1)
            )
    try:
        pdf = compose_pdf(composition_pages, layout=body.layout.model_dump())
        if len(pdf) > 100 * 1024 * 1024:
            raise DocVaultError("PAYLOAD_TOO_LARGE", detail="The composed PDF exceeds 100 MiB.")
        rendered_info = inspect_pdf(pdf)
        expected_sides = math.ceil(page_count / body.layout.cells_per_side)
        if rendered_info["page_count"] != expected_sides:
            raise DocVaultError(
                "BLOB_INVALID", detail="The print worker returned an invalid layout."
            )
        with OrmSession(_engine(request)) as session, session.begin():
            actor = auth.authenticate(session, keys, token)
            auth.verify_csrf(session, token, csrf)
            if actor.user_id != actor_id:
                raise DocVaultError("FORBIDDEN")
            for plan in plans:
                acl.require_document(
                    session,
                    actor.user_id,
                    plan.document_id,
                    acl.PRINT,
                    source_ip=source_ip,
                )
            stored_job = session.get(PrintJob, job_id, with_for_update=True)
            if stored_job is None:
                raise DocVaultError("NOT_FOUND")
            stored_job.status = PrintStatus.COMPLETED
            stored_job.completed_at = datetime.now(UTC)
            append_event(
                session,
                action="print_job.create",
                object_type="print_job",
                object_id=job_id,
                actor_id=actor.user_id,
                source_ip=source_ip,
                detail=_print_audit_detail(
                    body,
                    plans,
                    page_count=page_count,
                    sheet_count=sheet_count,
                    status="completed",
                ),
            )
    except DocVaultError as exc:
        _record_failure(
            request,
            body=body,
            job_id=job_id,
            actor_id=actor_id,
            source_ip=source_ip,
            plans=plans,
            page_count=page_count,
            sheet_count=sheet_count,
            error_code=exc.code,
        )
        raise

    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f'inline; filename="print-job-{job_id}.pdf"',
            "X-Print-Job-ID": str(job_id),
        },
    )


@router.post("/print-jobs", response_class=Response)
def create_print_job(
    body: PrintRequest,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    vault = _vault(request)
    keys = vault.keys
    source_ip = _source_ip(request)
    if source_ip is None:
        raise DocVaultError("BAD_REQUEST", detail="The request has no source address.")
    actor_id, plans, page_count = _plan_print_job(body, request, keys, token, csrf)
    job_id = uuid.uuid7()
    sheet_count = _persist_print_job(
        body,
        request,
        keys,
        actor_id,
        source_ip,
        job_id,
        plans,
        page_count,
        token,
        csrf,
    )
    return _compose_and_finalize(
        body,
        request,
        keys,
        token,
        csrf,
        actor_id,
        source_ip,
        job_id,
        plans,
        page_count,
        sheet_count,
    )


@router.get("/print-jobs", response_model=list[PrintJobResponse])
def list_print_jobs(
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> list[PrintJobResponse]:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        actor = auth.authenticate(session, keys, token)
        jobs = session.scalars(select(PrintJob).order_by(PrintJob.created_at.desc()).limit(100))
        return [
            _job_response(session, job)
            for job in jobs
            if _can_view_job(session, job, actor, _source_ip(request))
        ]


@router.get("/print-jobs/{job_id}", response_model=PrintJobResponse)
def get_print_job(
    job_id: uuid.UUID,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> PrintJobResponse:
    keys = _vault(request).keys
    with OrmSession(_engine(request)) as session, session.begin():
        actor = auth.authenticate(session, keys, token)
        job = session.get(PrintJob, job_id)
        if job is None or not _can_view_job(session, job, actor, _source_ip(request)):
            raise DocVaultError("NOT_FOUND")
        return _job_response(session, job)
