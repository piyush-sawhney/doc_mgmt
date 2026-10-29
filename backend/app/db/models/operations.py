"""ACLs, audit index, downloads, renditions, print records, and settings."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CHAR,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import HEX64, MONTH, Base, empty_json_sql, pg_enum
from app.db.enums import (
    AclEffect,
    AclObject,
    AclSubject,
    AuditOutcome,
    PrintStatus,
    RenditionKind,
)


class AclEntry(Base):
    __tablename__ = "acl_entries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid7)
    object_type: Mapped[AclObject] = mapped_column(pg_enum(AclObject, "acl_object"), nullable=False)
    object_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    subject_type: Mapped[AclSubject] = mapped_column(
        pg_enum(AclSubject, "acl_subject"), nullable=False
    )
    subject_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    capabilities: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    effect: Mapped[AclEffect] = mapped_column(pg_enum(AclEffect, "acl_effect"), nullable=False)
    row_version: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("1"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint(
            "object_type",
            "object_id",
            "subject_type",
            "subject_id",
            name="uq_acl_entries_target",
        ),
        CheckConstraint("capabilities BETWEEN 1 AND 63", name="capabilities_range"),
        CheckConstraint(
            "(capabilities & 2) = 0 OR (capabilities & 1) = 1", name="read_implies_view"
        ),
        CheckConstraint(
            "(capabilities & 32) = 0 OR (capabilities & 2) = 2", name="print_implies_read"
        ),
        CheckConstraint("row_version > 0", name="row_version_positive"),
        Index("ix_acl_entries_subject", "subject_type", "subject_id"),
        Index("ix_acl_entries_object", "object_type", "object_id"),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    seq: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(Text, nullable=False)
    object_type: Mapped[str] = mapped_column(Text, nullable=False)
    object_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    outcome: Mapped[AuditOutcome] = mapped_column(
        pg_enum(AuditOutcome, "audit_outcome"), nullable=False
    )
    source_ip: Mapped[str | None] = mapped_column(INET)
    detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text(empty_json_sql())
    )
    prev_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    file_month: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        CheckConstraint("octet_length(prev_hash) = 32", name="prev_hash_len"),
        CheckConstraint("octet_length(hash) = 32", name="hash_len"),
        CheckConstraint(f"file_month ~ '{MONTH}'", name="file_month_format"),
        Index("ix_audit_events_ts", "ts"),
        Index("ix_audit_events_actor", "actor_id"),
        Index("ix_audit_events_object", "object_type", "object_id"),
    )


class DownloadTicket(Base):
    __tablename__ = "download_tickets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid7)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("document_versions.id", ondelete="CASCADE"), nullable=False
    )
    rendition_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("renditions.id", ondelete="CASCADE")
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_ip: Mapped[str] = mapped_column(INET, nullable=False)

    __table_args__ = (
        CheckConstraint("octet_length(token_hash) = 32", name="token_hash_len"),
        Index("ix_download_tickets_expires", "expires_at"),
    )


class Rendition(Base):
    __tablename__ = "renditions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid7)
    version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("document_versions.id", ondelete="CASCADE"),
        nullable=False,
    )
    page_no: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[RenditionKind] = mapped_column(
        pg_enum(RenditionKind, "rendition_kind"), nullable=False
    )
    recipe_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    blob_addr: Mapped[str] = mapped_column(CHAR(64), nullable=False, unique=True)
    blob_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    plaintext_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    is_saved_recipe: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    page_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    width_px: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    height_px: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("page_no >= 1", name="page_no_positive"),
        CheckConstraint("plaintext_bytes >= 0", name="plaintext_bytes_non_negative"),
        CheckConstraint(f"recipe_hash ~ '{HEX64}'", name="recipe_hash_hex"),
        CheckConstraint(f"blob_addr ~ '{HEX64}'", name="blob_addr_hex"),
        Index(
            "ix_renditions_lookup",
            "version_id",
            "kind",
            "page_no",
            "recipe_hash",
        ),
        Index("ix_renditions_last_used", "last_used_at"),
    )


class PrintJob(Base):
    __tablename__ = "print_jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid7)
    requested_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    paper: Mapped[str] = mapped_column(Text, nullable=False)
    orientation: Mapped[str] = mapped_column(Text, nullable=False)
    cells_per_side: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    duplex: Mapped[bool] = mapped_column(Boolean, nullable=False)
    flip_edge: Mapped[str | None] = mapped_column(Text)
    margin_mm: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    gutter_mm: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    fit_mode: Mapped[str] = mapped_column(Text, nullable=False)
    item_count: Mapped[int] = mapped_column(Integer, nullable=False)
    page_count: Mapped[int] = mapped_column(Integer, nullable=False)
    sheet_count: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[PrintStatus] = mapped_column(
        pg_enum(PrintStatus, "print_status"), nullable=False
    )
    preset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    source_ip: Mapped[str] = mapped_column(INET, nullable=False)

    __table_args__ = (
        CheckConstraint("paper IN ('A4','Letter','Legal','A5','A3')", name="paper"),
        CheckConstraint("orientation IN ('portrait','landscape')", name="orientation"),
        CheckConstraint("cells_per_side IN (1,2,4,6,9)", name="cells_per_side"),
        CheckConstraint("flip_edge IS NULL OR flip_edge IN ('long','short')", name="flip_edge"),
        CheckConstraint("margin_mm >= 0", name="margin_non_negative"),
        CheckConstraint("gutter_mm >= 0", name="gutter_non_negative"),
        CheckConstraint("fit_mode IN ('contain','fill')", name="fit_mode"),
        CheckConstraint(
            "item_count >= 0 AND page_count >= 0 AND sheet_count >= 0", name="counts_non_negative"
        ),
        Index("ix_print_jobs_requested_by", "requested_by"),
        Index("ix_print_jobs_created", "created_at"),
    )


class PrintItem(Base):
    __tablename__ = "print_items"

    print_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("print_jobs.id", ondelete="CASCADE"), primary_key=True
    )
    position: Mapped[int] = mapped_column(Integer, primary_key=True)
    version_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    document_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    page_from: Mapped[int] = mapped_column(Integer, nullable=False)
    page_to: Mapped[int] = mapped_column(Integer, nullable=False)
    recipe_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)

    __table_args__ = (
        CheckConstraint("position >= 0", name="position_non_negative"),
        CheckConstraint("page_from >= 1 AND page_to >= page_from", name="page_range"),
        CheckConstraint(f"recipe_hash ~ '{HEX64}'", name="recipe_hash_hex"),
    )


class IdempotencyKey(Base):
    __tablename__ = "idempotency_keys"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    request_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    response_ref: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint("octet_length(request_hash) = 32", name="request_hash_len"),
        Index("ix_idempotency_keys_expires", "expires_at"),
    )


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    # ``vault_root`` is the single exception to encrypted settings (docs/04 §7).
    value: Mapped[str | None] = mapped_column(Text)
    value_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    row_version: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("1"))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "(value IS NULL) <> (value_enc IS NULL)",
            name="exactly_one_value",
        ),
        CheckConstraint("row_version > 0", name="row_version_positive"),
    )
