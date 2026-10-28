"""Entities, persons, roles between them, and typed identifiers."""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, pg_enum
from app.db.enums import AclMode, EntityStatus, EntityType, Gender, PersonRole


class Entity(Base):
    __tablename__ = "entities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid7)
    entity_type: Mapped[EntityType] = mapped_column(
        pg_enum(EntityType, "entity_type"), nullable=False
    )
    legal_name_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    display_name_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    name_blind: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    incorporation_date: Mapped[date | None] = mapped_column(Date)
    registered_address_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    contact_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    notes_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    acl_mode: Mapped[AclMode] = mapped_column(
        pg_enum(AclMode, "acl_mode"), nullable=False, server_default=AclMode.INHERIT.value
    )
    status: Mapped[EntityStatus] = mapped_column(
        pg_enum(EntityStatus, "entity_status"),
        nullable=False,
        server_default=EntityStatus.ACTIVE.value,
    )
    merged_into_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL")
    )
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

    __table_args__ = (
        CheckConstraint("octet_length(name_blind) = 33", name="name_blind_len"),
        CheckConstraint("row_version > 0", name="row_version_positive"),
        CheckConstraint("merged_into_id IS NULL OR merged_into_id <> id", name="merged_not_self"),
        CheckConstraint(
            "status <> 'merged' OR merged_into_id IS NOT NULL", name="merged_has_target"
        ),
        Index("ix_entities_name_blind", "name_blind"),
    )


class Person(Base):
    __tablename__ = "persons"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid7)
    full_name_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    name_blind: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    date_of_birth: Mapped[date | None] = mapped_column(Date)
    gender: Mapped[Gender | None] = mapped_column(pg_enum(Gender, "gender"))
    notes_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    row_version: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("1"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("octet_length(name_blind) = 33", name="name_blind_len"),
        CheckConstraint("row_version > 0", name="row_version_positive"),
        Index("ix_persons_name_blind", "name_blind"),
    )


class EntityPerson(Base):
    __tablename__ = "entity_person"

    entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), primary_key=True
    )
    person_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("persons.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[PersonRole] = mapped_column(pg_enum(PersonRole, "person_role"), primary_key=True)
    effective_from: Mapped[date | None] = mapped_column(Date)
    effective_to: Mapped[date | None] = mapped_column(Date)

    __table_args__ = (
        CheckConstraint(
            "effective_to IS NULL OR effective_from IS NULL OR effective_to >= effective_from",
            name="effective_range",
        ),
        Index(
            "uq_entity_person_self",
            "entity_id",
            unique=True,
            postgresql_where=text("role = 'self'"),
        ),
    )


class Identifier(Base):
    __tablename__ = "identifiers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid7)
    entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    id_type: Mapped[str] = mapped_column(Text, nullable=False)
    value_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    value_blind: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    label: Mapped[str | None] = mapped_column(Text)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    duplicate_ack_of: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("identifiers.id", ondelete="SET NULL")
    )
    notes_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    row_version: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("1"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(
            "id_type IN ('pan','aadhaar','gstin','cin','din','passport','tan','other')",
            name="id_type",
        ),
        CheckConstraint("octet_length(value_blind) = 33", name="value_blind_len"),
        CheckConstraint("row_version > 0", name="row_version_positive"),
        CheckConstraint("duplicate_ack_of IS NULL OR duplicate_ack_of <> id", name="ack_not_self"),
        CheckConstraint(
            "verified = false OR (verified_at IS NOT NULL AND verified_by IS NOT NULL)",
            name="verified_has_evidence",
        ),
        Index(
            "ix_identifiers_type_value",
            "id_type",
            "value_blind",
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index(
            "ix_identifiers_entity",
            "entity_id",
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )
