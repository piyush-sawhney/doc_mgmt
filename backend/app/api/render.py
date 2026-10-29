"""ACL-gated rendition generation, cache settings, and one-use tickets."""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Cookie, Header, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as OrmSession

from app.core.errors import DocVaultError
from app.crypto.canonical import canonical_json
from app.crypto.keys import VaultKeys, decrypt_column, encrypt_column
from app.db.enums import RenditionKind
from app.db.models.documents import DocumentVersion, VersionRenderSettings
from app.db.models.operations import DownloadTicket, Rendition
from app.render.worker_client import render_page
from app.services import acl, auth
from app.services.audit import append_event
from app.vault.blobs import decrypt_blob, encrypt_blob, read_blob_file, write_blob_file
from app.vault.session import VaultManager

router = APIRouter(prefix="/api/v1", tags=["render"])


class RenderRecipe(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rotate: int = Field(default=0, ge=0, le=270)
    straighten: float = Field(default=0, ge=-15, le=15)
    crop: tuple[float, float, float, float] | None = None
    brightness: int = Field(default=0, ge=-100, le=100)
    contrast: int = Field(default=0, ge=-100, le=100)
    gamma: float = Field(default=1, ge=0.1, le=3)
    grayscale: bool = False
    invert: bool = False
    threshold: int | None = Field(default=None, ge=0, le=255)
    despeckle: bool = False
    auto_trim: bool = False

    @model_validator(mode="after")
    def validate_recipe(self) -> RenderRecipe:
        if self.rotate % 90:
            raise ValueError("rotate must be a multiple of 90 degrees")
        if self.crop is not None:
            left, top, right, bottom = self.crop
            if not (0 <= left < right <= 1 and 0 <= top < bottom <= 1):
                raise ValueError("crop must have positive area inside the unit square")
        if self.threshold is not None and not self.grayscale:
            raise ValueError("threshold requires grayscale")
        return self


class RenditionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    page: int = Field(ge=1)
    kind: RenditionKind
    recipe: RenderRecipe
    break_glass_reason: str | None = Field(default=None, max_length=500)


class RenditionTicketResponse(BaseModel):
    url: str
    expires_at: datetime
    page: int
    kind: RenditionKind
    page_count: int
    width: int
    height: int


def _engine(request: Request) -> Engine:
    engine = getattr(request.app.state, "db_engine", None)
    if not isinstance(engine, Engine):
        raise DocVaultError("DB_UNAVAILABLE")
    return engine


def _vault(request: Request) -> VaultManager:
    vault = getattr(request.app.state, "vault", None)
    if not isinstance(vault, VaultManager):
        raise DocVaultError("NOT_READY", detail="The vault is not open.")
    return vault


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _keys(request: Request) -> VaultKeys:
    return _vault(request).keys


def _actor(
    session: OrmSession,
    keys: VaultKeys,
    token: str | None,
    csrf: str | None = None,
) -> auth.AuthenticatedSession:
    actor = auth.authenticate(session, keys, token)
    if csrf is not None:
        auth.verify_csrf(session, token, csrf)
    return actor


def _unlink_blob_paths(paths: list[Path]) -> None:
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            raise DocVaultError(
                "BLOB_INVALID", detail="A cached rendition could not be removed."
            ) from exc


def _recipe_hash(recipe: RenderRecipe) -> str:
    return hashlib.sha256(canonical_json(recipe.model_dump(mode="json"))).hexdigest()


def _saved_recipe(
    session: OrmSession,
    keys: VaultKeys,
    version_id: uuid.UUID,
) -> tuple[str, dict[str, Any]]:
    stored = session.get(VersionRenderSettings, version_id)
    if stored is None:
        recipe = RenderRecipe().model_dump(mode="json")
        return _recipe_hash(RenderRecipe()), recipe
    raw = decrypt_column(
        keys.meta_key,
        "version_render_settings",
        "recipe_enc",
        stored.recipe_enc,
    )
    if raw is None:
        raise DocVaultError("COLUMN_TAMPERED", detail="The saved render recipe could not be read.")
    try:
        parsed_recipe = RenderRecipe.model_validate_json(raw)
    except ValueError as exc:
        raise DocVaultError(
            "COLUMN_TAMPERED", detail="The saved render recipe is invalid."
        ) from exc
    return stored.recipe_hash, parsed_recipe.model_dump(mode="json")


@router.get(
    "/documents/{document_id}/versions/{version_no}/render-settings",
    response_model=RenderRecipe,
)
def get_render_settings(
    document_id: uuid.UUID,
    version_no: int,
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
) -> RenderRecipe:
    keys = _keys(request)
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token)
        document = acl.require_document(
            session, actor.user_id, document_id, acl.VIEW, source_ip=_source_ip(request)
        )
        version = session.scalar(
            select(DocumentVersion).where(
                DocumentVersion.document_id == document.id,
                DocumentVersion.version_no == version_no,
            )
        )
        if version is None:
            raise DocVaultError("NOT_FOUND")
        settings = session.get(VersionRenderSettings, version.id)
        if settings is None:
            response.headers["ETag"] = 'W/"0"'
            return RenderRecipe()
        response.headers["ETag"] = f'W/"{settings.row_version}"'
        _, raw_recipe = _saved_recipe(session, keys, version.id)
        return RenderRecipe.model_validate(raw_recipe)


@router.put(
    "/documents/{document_id}/versions/{version_no}/render-settings",
    response_model=RenderRecipe,
)
def put_render_settings(
    document_id: uuid.UUID,
    version_no: int,
    body: RenderRecipe,
    request: Request,
    response: Response,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> RenderRecipe:
    if if_match is None:
        raise DocVaultError("PRECONDITION_REQUIRED")
    match = re.fullmatch(r'(?:W/)?"([0-9]+)"', if_match.strip())
    if match is None:
        raise DocVaultError("BAD_REQUEST", detail="If-Match must contain a numeric ETag.")
    expected = int(match.group(1))
    keys = _keys(request)
    paths_to_delete: list[Path] = []
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, csrf)
        document = acl.require_document(
            session, actor.user_id, document_id, acl.WRITE, source_ip=_source_ip(request)
        )
        version = session.scalar(
            select(DocumentVersion).where(
                DocumentVersion.document_id == document.id,
                DocumentVersion.version_no == version_no,
            )
        )
        if version is None:
            raise DocVaultError("NOT_FOUND")
        current = session.get(VersionRenderSettings, version.id)
        actual = current.row_version if current is not None else 0
        if expected != actual:
            raise DocVaultError("CONFLICT", detail="The render settings changed. Reload and retry.")
        new_hash = _recipe_hash(body)
        now = datetime.now(UTC)
        if current is None:
            current = VersionRenderSettings(
                version_id=version.id,
                recipe_enc=encrypt_column(
                    keys.meta_key,
                    "version_render_settings",
                    "recipe_enc",
                    canonical_json(body.model_dump(mode="json")).decode("utf-8"),
                )
                or b"",
                recipe_hash=new_hash,
                updated_by=actor.user_id,
            )
            session.add(current)
        else:
            current.recipe_enc = (
                encrypt_column(
                    keys.meta_key,
                    "version_render_settings",
                    "recipe_enc",
                    canonical_json(body.model_dump(mode="json")).decode("utf-8"),
                )
                or b""
            )
            current.recipe_hash = new_hash
            current.row_version += 1
            current.updated_at = now
            current.updated_by = actor.user_id
        cached = list(
            session.scalars(
                select(Rendition).where(
                    Rendition.version_id == version.id,
                    Rendition.is_saved_recipe.is_(True),
                    Rendition.recipe_hash != new_hash,
                )
            )
        )
        for rendition in cached:
            paths_to_delete.append(_vault(request).paths.blob(rendition.blob_addr))
            session.delete(rendition)
        session.flush()
        append_event(
            session,
            action="document.render_settings_changed",
            object_type="document",
            object_id=document.id,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
            detail={"recipe_hash": new_hash},
        )
        response.headers["ETag"] = f'W/"{current.row_version}"'
    _unlink_blob_paths(paths_to_delete)
    return body


@router.delete(
    "/documents/{document_id}/versions/{version_no}/render-settings",
    status_code=204,
)
def delete_render_settings(
    document_id: uuid.UUID,
    version_no: int,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    keys = _keys(request)
    paths_to_delete: list[Path] = []
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token, csrf)
        document = acl.require_document(
            session, actor.user_id, document_id, acl.WRITE, source_ip=_source_ip(request)
        )
        version = session.scalar(
            select(DocumentVersion).where(
                DocumentVersion.document_id == document.id,
                DocumentVersion.version_no == version_no,
            )
        )
        if version is None:
            raise DocVaultError("NOT_FOUND")
        settings = session.get(VersionRenderSettings, version.id)
        if settings is not None:
            session.delete(settings)
        cached = list(
            session.scalars(
                select(Rendition).where(
                    Rendition.version_id == version.id,
                    Rendition.is_saved_recipe.is_(True),
                )
            )
        )
        for rendition in cached:
            paths_to_delete.append(_vault(request).paths.blob(rendition.blob_addr))
            session.delete(rendition)
        append_event(
            session,
            action="document.render_settings_changed",
            object_type="document",
            object_id=document.id,
            actor_id=actor.user_id,
            source_ip=_source_ip(request),
            detail={"recipe_hash": _recipe_hash(RenderRecipe()), "reset": True},
        )
    _unlink_blob_paths(paths_to_delete)
    return Response(status_code=204)


@router.post(
    "/documents/{document_id}/versions/{version_no}/renditions",
    response_model=RenditionTicketResponse,
)
def create_rendition_ticket(  # noqa: PLR0915
    document_id: uuid.UUID,
    version_no: int,
    body: RenditionRequest,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> RenditionTicketResponse:
    keys = _keys(request)
    source_ip = _source_ip(request)
    if source_ip is None:
        raise DocVaultError("BAD_REQUEST", detail="The request has no source address.")
    generated_path: Path | None = None
    paths_to_delete: list[Path] = []
    try:
        with OrmSession(_engine(request)) as session, session.begin():
            actor = _actor(session, keys, token, csrf)
            document = acl.require_document(
                session,
                actor.user_id,
                document_id,
                acl.READ,
                source_ip=source_ip,
                break_glass_reason=body.break_glass_reason,
            )
            version = session.scalar(
                select(DocumentVersion).where(
                    DocumentVersion.document_id == document.id,
                    DocumentVersion.version_no == version_no,
                )
            )
            if version is None:
                raise DocVaultError("NOT_FOUND")
            requested_recipe = body.recipe
            recipe_hash = _recipe_hash(requested_recipe)
            saved_hash, _ = _saved_recipe(session, keys, version.id)
            should_cache = recipe_hash == saved_hash
            settings = getattr(request.app.state, "settings", None)
            cache_limit = getattr(getattr(settings, "render", None), "cache_bytes", 0)
            rendition = None
            if should_cache and cache_limit > 0:
                rendition = session.scalar(
                    select(Rendition).where(
                        Rendition.version_id == version.id,
                        Rendition.page_no == body.page,
                        Rendition.kind == body.kind,
                        Rendition.recipe_hash == recipe_hash,
                        Rendition.is_saved_recipe.is_(True),
                    )
                )
            if rendition is None:
                source_address = version.derived_pdf_addr or version.blob_addr
                source_salt = version.derived_pdf_salt or version.blob_salt
                source_mime = "application/pdf" if version.derived_pdf_addr else version.mime
                blob_path = _vault(request).paths.blob(source_address)
                source = decrypt_blob(
                    read_blob_file(blob_path),
                    keys,
                    salt=source_salt,
                    expected_address=source_address,
                ).plaintext
                rendered, info = render_page(
                    source,
                    mime=source_mime,
                    page=body.page,
                    recipe=requested_recipe.model_dump(mode="json"),
                    max_edge=2400 if body.kind == RenditionKind.PAGE else 1200,
                )
                encrypted = encrypt_blob(rendered, keys)
                rendition_path = _vault(request).paths.blob(encrypted.address)
                generated_path = rendition_path
                temporary_path = _vault(request).paths.tmp / f"{uuid.uuid4().hex}.part"
                write_blob_file(encrypted, rendition_path, temporary_path)
                persist_cache = should_cache and cache_limit >= len(rendered)
                if persist_cache:
                    used_bytes = (
                        session.scalar(
                            select(func.coalesce(func.sum(Rendition.plaintext_bytes), 0)).where(
                                Rendition.is_saved_recipe.is_(True)
                            )
                        )
                        or 0
                    )
                    cache_rows = list(
                        session.scalars(
                            select(Rendition)
                            .where(Rendition.is_saved_recipe.is_(True))
                            .order_by(Rendition.last_used_at)
                        )
                    )
                    for cached_item in cache_rows:
                        if used_bytes + len(rendered) <= cache_limit:
                            break
                        paths_to_delete.append(_vault(request).paths.blob(cached_item.blob_addr))
                        used_bytes -= cached_item.plaintext_bytes
                        session.delete(cached_item)
                rendition = Rendition(
                    version_id=version.id,
                    page_no=body.page,
                    kind=body.kind,
                    recipe_hash=recipe_hash,
                    blob_addr=encrypted.address,
                    blob_salt=encrypted.salt,
                    plaintext_bytes=len(rendered),
                    is_saved_recipe=persist_cache,
                    page_count=info["page_count"],
                    width_px=info["width"],
                    height_px=info["height"],
                )
                session.add(rendition)
                session.flush()
            else:
                info = {
                    "page_count": rendition.page_count,
                    "width": rendition.width_px,
                    "height": rendition.height_px,
                }
                rendition.last_used_at = datetime.now(UTC)
            raw_token = secrets.token_urlsafe(32)
            expires_at = datetime.now(UTC) + timedelta(seconds=60)
            session.add(
                DownloadTicket(
                    token_hash=hashlib.sha256(raw_token.encode("ascii")).digest(),
                    version_id=version.id,
                    rendition_id=rendition.id,
                    user_id=actor.user_id,
                    expires_at=expires_at,
                    source_ip=source_ip,
                )
            )
            append_event(
                session,
                action="document.rendition_ticket",
                object_type="document",
                object_id=document.id,
                actor_id=actor.user_id,
                source_ip=source_ip,
                detail={"version_id": str(version.id), "page": body.page, "kind": body.kind.value},
            )
            result = RenditionTicketResponse(
                url=f"/api/v1/renditions/{raw_token}",
                expires_at=expires_at,
                page=body.page,
                kind=body.kind,
                page_count=info["page_count"],
                width=info["width"],
                height=info["height"],
            )
    except BaseException:
        if generated_path is not None:
            generated_path.unlink(missing_ok=True)
        raise
    _unlink_blob_paths(paths_to_delete)
    return result


@router.get("/renditions/{ticket_token}")
def redeem_rendition_ticket(
    ticket_token: str,
    request: Request,
    token: Annotated[str | None, Cookie(alias="dv_session")] = None,
    break_glass_reason: Annotated[str | None, Header(alias="X-Break-Glass-Reason")] = None,
) -> Response:
    keys = _keys(request)
    source_ip = _source_ip(request)
    if source_ip is None:
        raise DocVaultError("GONE")
    ticket_hash = hashlib.sha256(ticket_token.encode("utf-8")).digest()
    transient_blob: str | None = None
    with OrmSession(_engine(request)) as session, session.begin():
        actor = _actor(session, keys, token)
        ticket = session.scalar(
            select(DownloadTicket).where(DownloadTicket.token_hash == ticket_hash).with_for_update()
        )
        now = datetime.now(UTC)
        if (
            ticket is None
            or ticket.rendition_id is None
            or ticket.used_at is not None
            or ticket.expires_at <= now
            or ticket.user_id != actor.user_id
            or str(ticket.source_ip) != source_ip
        ):
            raise DocVaultError("GONE")
        rendition = session.get(Rendition, ticket.rendition_id)
        version = session.get(DocumentVersion, ticket.version_id)
        if rendition is None or version is None:
            raise DocVaultError("GONE")
        document = acl.require_document(
            session,
            actor.user_id,
            version.document_id,
            acl.READ,
            source_ip=source_ip,
            break_glass_reason=break_glass_reason,
        )
        encrypted = read_blob_file(_vault(request).paths.blob(rendition.blob_addr))
        png = decrypt_blob(
            encrypted,
            keys,
            salt=rendition.blob_salt,
            expected_address=rendition.blob_addr,
        ).plaintext
        ticket.used_at = now
        if not rendition.is_saved_recipe:
            transient_blob = rendition.blob_addr
            session.delete(rendition)
        append_event(
            session,
            action="document.rendition",
            object_type="document",
            object_id=document.id,
            actor_id=actor.user_id,
            source_ip=source_ip,
            detail={"version_id": str(version.id), "page": rendition.page_no},
        )
    if transient_blob is not None:
        _vault(request).paths.blob(transient_blob).unlink(missing_ok=True)
    return Response(
        content=png,
        media_type="image/png",
        headers={"Cache-Control": "no-store", "Content-Disposition": "inline"},
    )
