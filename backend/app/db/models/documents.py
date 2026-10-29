"""Document types, documents, versions, links, tags, and render recipes."""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    CHAR,
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import CITEXT, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import HEX64, Base, pg_enum
from app.db.enums import (
    AclMode,
    ConfLevel,
    DocStatus,
    LinkRole,
    SideKind,
)


class DocType(Base):
    __tablename__ = "doc_types"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid7)
    code: Mapped[str] = mapped_column(CITEXT, nullable=False, unique=True)
    name_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("doc_types.id", ondelete="RESTRICT")
    )
    default_confidentiality: Mapped[ConfLevel] = mapped_column(
        pg_enum(ConfLevel, "conf_level"),
        nullable=False,
        server_default=ConfLevel.NORMAL.value,
    )
    retention_months: Mapped[int | None] = mapped_column(Integer)
    requires_expiry: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    side: Mapped[SideKind | None] = mapped_column(pg_enum(SideKind, "side_kind"))
    purpose_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    row_version: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("1"))

    __table_args__ = (
        CheckConstraint("parent_id IS NULL OR parent_id <> id", name="parent_not_self"),
        CheckConstraint(
            "retention_months IS NULL OR retention_months > 0", name="retention_positive"
        ),
        CheckConstraint("row_version > 0", name="row_version_positive"),
        Index("ix_doc_types_parent", "parent_id"),
    )


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid7)
    doc_type_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("doc_types.id", ondelete="RESTRICT"), nullable=False
    )
    title_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    title_blind: Mapped[bytes | None] = mapped_column(LargeBinary)
    issuer_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    doc_number_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    issue_date: Mapped[date | None] = mapped_column(Date)
    expiry_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[DocStatus] = mapped_column(
        pg_enum(DocStatus, "doc_status"),
        nullable=False,
        server_default=DocStatus.ACTIVE.value,
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    acl_mode: Mapped[AclMode] = mapped_column(
        pg_enum(AclMode, "acl_mode"), nullable=False, server_default=AclMode.INHERIT.value
    )
    confidentiality: Mapped[ConfLevel] = mapped_column(
        pg_enum(ConfLevel, "conf_level"), nullable=False
    )
    legal_hold: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    current_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "document_versions.id",
            use_alter=True,
            name="fk_documents_current_version_id_document_versions",
        ),
    )
    version_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
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
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    purge_after: Mapped[date | None] = mapped_column(Date)
    purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("octet_length(title_blind) = 33 OR title_blind IS NULL", name="title_len"),
        CheckConstraint("version_count >= 0", name="version_count_non_negative"),
        CheckConstraint("row_version > 0", name="row_version_positive"),
        CheckConstraint(
            "purged_at IS NULL OR deleted_at IS NOT NULL", name="purged_implies_deleted"
        ),
        CheckConstraint("purged_at IS NULL OR legal_hold = false", name="legal_hold_blocks_purge"),
        Index(
            "ix_documents_doc_type",
            "doc_type_id",
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index(
            "ix_documents_expiry",
            "expiry_date",
            postgresql_where=text("deleted_at IS NULL AND expiry_date IS NOT NULL"),
        ),
        Index(
            "ix_documents_owner",
            "owner_id",
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class DocumentVersion(Base):
    __tablename__ = "document_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid7)
    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("documents.id", ondelete="RESTRICT"), nullable=False
    )
    version_no: Mapped[int] = mapped_column(Integer, nullable=False)
    blob_addr: Mapped[str] = mapped_column(CHAR(64), nullable=False, unique=True)
    blob_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    plaintext_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    stored_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime: Mapped[str] = mapped_column(Text, nullable=False)
    original_filename_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    derived_pdf_addr: Mapped[str | None] = mapped_column(CHAR(64), unique=True)
    derived_pdf_salt: Mapped[bytes | None] = mapped_column(LargeBinary)
    derived_pdf_pages: Mapped[int | None] = mapped_column(Integer)
    derived_pdf_size: Mapped[int | None] = mapped_column(BigInteger)
    note_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    uploaded_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("document_id", "version_no", name="uq_document_versions_number"),
        CheckConstraint("version_no >= 1", name="version_no_positive"),
        CheckConstraint("plaintext_size >= 0", name="plaintext_size_non_negative"),
        CheckConstraint("stored_size >= 0", name="stored_size_non_negative"),
        CheckConstraint("octet_length(blob_salt) = 16", name="blob_salt_len"),
        CheckConstraint(f"blob_addr ~ '{HEX64}'", name="blob_addr_hex"),
        CheckConstraint(
            f"derived_pdf_addr IS NULL OR derived_pdf_addr ~ '{HEX64}'",
            name="derived_pdf_addr_hex",
        ),
        CheckConstraint(
            "(derived_pdf_addr IS NULL) = (derived_pdf_salt IS NULL)",
            name="derived_pdf_pair",
        ),
        CheckConstraint(
            "(derived_pdf_addr IS NULL) = (derived_pdf_pages IS NULL)",
            name="derived_pdf_pages_pair",
        ),
        CheckConstraint(
            "(derived_pdf_addr IS NULL) = (derived_pdf_size IS NULL)",
            name="derived_pdf_size_pair",
        ),
        CheckConstraint(
            "derived_pdf_pages IS NULL OR derived_pdf_pages > 0",
            name="derived_pdf_pages_positive",
        ),
        CheckConstraint(
            "derived_pdf_size IS NULL OR derived_pdf_size >= 0",
            name="derived_pdf_size_non_negative",
        ),
        CheckConstraint(
            "derived_pdf_salt IS NULL OR octet_length(derived_pdf_salt) = 16",
            name="derived_pdf_salt_len",
        ),
        Index("ix_document_versions_document", "document_id"),
    )


class DocumentEntityLink(Base):
    __tablename__ = "document_entity_links"

    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), primary_key=True
    )
    link_role: Mapped[LinkRole] = mapped_column(pg_enum(LinkRole, "link_role"), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid7)
    name_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    name_blind: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    color: Mapped[str | None] = mapped_column(Text)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    row_version: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("1"))

    __table_args__ = (
        CheckConstraint("octet_length(name_blind) = 33", name="name_blind_len"),
        CheckConstraint("row_version > 0", name="row_version_positive"),
    )


class DocumentTag(Base):
    __tablename__ = "document_tags"

    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    tag_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True
    )


class VersionRenderSettings(Base):
    __tablename__ = "version_render_settings"

    version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("document_versions.id", ondelete="CASCADE"),
        primary_key=True,
    )
    recipe_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    recipe_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    row_version: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("1"))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )

    __table_args__ = (
        CheckConstraint(f"recipe_hash ~ '{HEX64}'", name="recipe_hash_hex"),
        CheckConstraint("row_version > 0", name="row_version_positive"),
    )
