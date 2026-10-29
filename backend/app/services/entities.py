"""Entity, identifier, and person persistence operations."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, date, datetime

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.errors import DocVaultError
from app.crypto.keys import (
    VaultKeys,
    blind_index,
    decrypt_column,
    encrypt_column,
    normalize_identifier,
)
from app.db.enums import EntityStatus, EntityType, Gender, PersonRole
from app.db.models.entities import Entity, EntityPerson, Identifier, Person
from app.db.models.operations import AuditEvent
from app.services.audit import append_event

IDENTIFIER_TYPES = frozenset({"pan", "aadhaar", "gstin", "cin", "din", "passport", "tan", "other"})


def _required(value: str, field: str, *, maximum: int) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise DocVaultError(
            "VALIDATION_FAILED",
            fields=[
                {
                    "field": field,
                    "code": "invalid_length",
                    "message": f"Use 1-{maximum} characters.",
                }
            ],
        )
    return normalized


def _validate_identifier_type(id_type: str) -> str:
    normalized = id_type.strip().lower()
    if normalized not in IDENTIFIER_TYPES:
        raise DocVaultError(
            "VALIDATION_FAILED",
            fields=[
                {
                    "field": "id_type",
                    "code": "unsupported",
                    "message": "Unsupported identifier type.",
                }
            ],
        )
    return normalized


def _identifier_lock_key(id_type: str, value_blind: bytes) -> int:
    digest = hashlib.sha256(id_type.encode("ascii") + b"\x00" + value_blind).digest()[:8]
    return int.from_bytes(digest, byteorder="big", signed=True)


def _check_identifier_duplicate(
    session: Session,
    *,
    id_type: str,
    value_blind: bytes,
    entity_id: uuid.UUID,
    duplicate_ack_of: uuid.UUID | None,
    exclude_id: uuid.UUID | None = None,
) -> None:
    session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_key)"),
        {"lock_key": _identifier_lock_key(id_type, value_blind)},
    )
    matches = tuple(
        session.execute(
            select(Identifier).where(
                Identifier.id_type == id_type,
                Identifier.value_blind == value_blind,
                Identifier.deleted_at.is_(None),
                *([Identifier.id != exclude_id] if exclude_id is not None else []),
            )
        ).scalars()
    )
    if not matches:
        if duplicate_ack_of is not None:
            raise DocVaultError(
                "VALIDATION_FAILED",
                fields=[
                    {
                        "field": "duplicate_ack_of",
                        "code": "not_found",
                        "message": "The acknowledged identifier does not exist.",
                    }
                ],
            )
        return
    acknowledged = next((item for item in matches if item.id == duplicate_ack_of), None)
    if acknowledged is None or acknowledged.entity_id == entity_id:
        raise DocVaultError(
            "CONFLICT",
            detail=(
                "This identifier is already in use; acknowledge an existing identifier "
                "to record a duplicate."
            ),
        )


def add_identifier(
    session: Session,
    keys: VaultKeys,
    *,
    entity_id: uuid.UUID,
    actor_id: uuid.UUID,
    id_type: str,
    value: str,
    label: str | None = None,
    duplicate_ack_of: uuid.UUID | None = None,
    source_ip: str | None = None,
) -> Identifier:
    normalized_type = _validate_identifier_type(id_type)
    normalized_value = _required(normalize_identifier(value), "value", maximum=256)
    value_blind = blind_index(keys.bidx_key, normalized_type, normalized_value)
    _check_identifier_duplicate(
        session,
        id_type=normalized_type,
        value_blind=value_blind,
        entity_id=entity_id,
        duplicate_ack_of=duplicate_ack_of,
    )
    if duplicate_ack_of is not None:
        acknowledged = session.get(Identifier, duplicate_ack_of)
        if (
            acknowledged is None
            or acknowledged.id_type != normalized_type
            or acknowledged.value_blind != value_blind
        ):
            raise DocVaultError(
                "VALIDATION_FAILED",
                fields=[
                    {
                        "field": "duplicate_ack_of",
                        "code": "mismatch",
                        "message": "The acknowledged identifier must have the same type and value.",
                    }
                ],
            )
    record = Identifier(
        entity_id=entity_id,
        id_type=normalized_type,
        value_enc=encrypt_column(keys.meta_key, "identifiers", "value_enc", normalized_value)
        or b"",
        value_blind=value_blind,
        label=_required(label, "label", maximum=100) if label else None,
        duplicate_ack_of=duplicate_ack_of,
        created_by=actor_id,
    )
    session.add(record)
    session.flush()
    append_event(
        session,
        action="identifier.create",
        object_type="identifier",
        object_id=record.id,
        actor_id=actor_id,
        source_ip=source_ip,
        detail={"entity_id": str(entity_id), "id_type": normalized_type},
    )
    return record


def create_entity(
    session: Session,
    keys: VaultKeys,
    *,
    actor_id: uuid.UUID,
    entity_type: EntityType,
    legal_name: str,
    display_name: str | None = None,
    incorporation_date: date | None = None,
    registered_address: str | None = None,
    contact: str | None = None,
    notes: str | None = None,
    identifiers: tuple[dict[str, str], ...] = (),
    source_ip: str | None = None,
) -> Entity:
    name = _required(legal_name, "legal_name", maximum=300)
    display = _required(display_name, "display_name", maximum=300) if display_name else None
    record = Entity(
        entity_type=entity_type,
        legal_name_enc=encrypt_column(keys.meta_key, "entities", "legal_name_enc", name) or b"",
        display_name_enc=encrypt_column(keys.meta_key, "entities", "display_name_enc", display),
        name_blind=blind_index(keys.bidx_key, "entity_name", name),
        incorporation_date=incorporation_date,
        registered_address_enc=encrypt_column(
            keys.meta_key, "entities", "registered_address_enc", registered_address
        ),
        contact_enc=encrypt_column(keys.meta_key, "entities", "contact_enc", contact),
        notes_enc=encrypt_column(keys.meta_key, "entities", "notes_enc", notes),
        created_by=actor_id,
        updated_by=actor_id,
    )
    session.add(record)
    session.flush()

    if entity_type is EntityType.INDIVIDUAL:
        person = Person(
            full_name_enc=encrypt_column(keys.meta_key, "persons", "full_name_enc", name) or b"",
            name_blind=blind_index(keys.bidx_key, "person_name", name),
            created_by=actor_id,
        )
        session.add(person)
        session.flush()
        session.add(EntityPerson(entity_id=record.id, person_id=person.id, role=PersonRole.SELF))

    for identifier in identifiers:
        add_identifier(
            session,
            keys,
            entity_id=record.id,
            actor_id=actor_id,
            id_type=identifier["id_type"],
            value=identifier["value"],
            label=identifier.get("label"),
            source_ip=source_ip,
        )

    append_event(
        session,
        action="entity.create",
        object_type="entity",
        object_id=record.id,
        actor_id=actor_id,
        source_ip=source_ip,
        detail={"entity_type": entity_type.value},
    )
    return record


def entity_data(record: Entity, keys: VaultKeys) -> dict[str, object]:
    return {
        "id": record.id,
        "entity_type": record.entity_type,
        "legal_name": decrypt_column(
            keys.meta_key, "entities", "legal_name_enc", record.legal_name_enc
        ),
        "display_name": decrypt_column(
            keys.meta_key, "entities", "display_name_enc", record.display_name_enc
        ),
        "incorporation_date": record.incorporation_date,
        "registered_address": decrypt_column(
            keys.meta_key, "entities", "registered_address_enc", record.registered_address_enc
        ),
        "contact": decrypt_column(keys.meta_key, "entities", "contact_enc", record.contact_enc),
        "notes": decrypt_column(keys.meta_key, "entities", "notes_enc", record.notes_enc),
        "acl_mode": record.acl_mode,
        "status": record.status,
        "row_version": record.row_version,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }


def identifier_data(
    record: Identifier, keys: VaultKeys, *, reveal: bool = False
) -> dict[str, object]:
    value = decrypt_column(keys.meta_key, "identifiers", "value_enc", record.value_enc) or ""
    masked = value if reveal else f"{value[:2]}{'*' * max(6, len(value) - 4)}{value[-2:]}"
    return {
        "id": record.id,
        "id_type": record.id_type,
        "value": value if reveal else None,
        "value_masked": masked,
        "label": record.label,
        "verified": record.verified,
        "duplicate_ack_of": record.duplicate_ack_of,
        "row_version": record.row_version,
    }


def patch_entity(
    session: Session,
    keys: VaultKeys,
    entity_id: uuid.UUID,
    actor_id: uuid.UUID,
    expected_version: int,
    changes: dict[str, object],
    *,
    source_ip: str | None,
) -> Entity:
    record = session.execute(
        select(Entity)
        .where(Entity.id == entity_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if record is None:
        raise DocVaultError("NOT_FOUND")
    if record.row_version != expected_version:
        raise DocVaultError("CONFLICT", detail="The entity changed. Reload and retry.")

    for field, column in (
        ("legal_name", "legal_name_enc"),
        ("display_name", "display_name_enc"),
        ("registered_address", "registered_address_enc"),
        ("contact", "contact_enc"),
        ("notes", "notes_enc"),
    ):
        if field in changes:
            value = changes[field]
            if field == "legal_name":
                if not isinstance(value, str):
                    raise DocVaultError("VALIDATION_FAILED", detail="legal_name cannot be null.")
                value = _required(value, field, maximum=300)
                record.name_blind = blind_index(keys.bidx_key, "entity_name", value)
            elif value is not None and not isinstance(value, str):
                raise DocVaultError(
                    "VALIDATION_FAILED", detail=f"{field} must be a string or null."
                )
            if isinstance(value, str) and field != "legal_name":
                value = _required(value, field, maximum=4000)
            setattr(record, column, encrypt_column(keys.meta_key, "entities", column, value))
    if "incorporation_date" in changes:
        value = changes["incorporation_date"]
        if value is not None and not isinstance(value, date):
            raise DocVaultError("VALIDATION_FAILED", detail="incorporation_date is invalid.")
        record.incorporation_date = value
    if "status" in changes:
        status = changes["status"]
        if not isinstance(status, EntityStatus):
            raise DocVaultError("VALIDATION_FAILED", detail="status is invalid.")
        record.status = status

    record.row_version += 1
    record.updated_at = datetime.now(UTC)
    record.updated_by = actor_id
    session.flush()
    append_event(
        session,
        action="entity.update",
        object_type="entity",
        object_id=record.id,
        actor_id=actor_id,
        source_ip=source_ip,
        detail={"fields": sorted(changes)},
    )
    return record


def soft_delete_entity(
    session: Session,
    entity: Entity,
    actor_id: uuid.UUID,
    *,
    source_ip: str | None,
) -> None:
    entity.deleted_at = datetime.now(UTC)
    entity.updated_at = entity.deleted_at
    entity.updated_by = actor_id
    entity.row_version += 1
    session.flush()
    append_event(
        session,
        action="entity.delete",
        object_type="entity",
        object_id=entity.id,
        actor_id=actor_id,
        source_ip=source_ip,
    )


def restore_entity(
    session: Session,
    entity: Entity,
    actor_id: uuid.UUID,
    *,
    source_ip: str | None,
) -> None:
    entity.deleted_at = None
    entity.updated_at = datetime.now(UTC)
    entity.updated_by = actor_id
    entity.row_version += 1
    session.flush()
    append_event(
        session,
        action="entity.restore",
        object_type="entity",
        object_id=entity.id,
        actor_id=actor_id,
        source_ip=source_ip,
    )


def list_identifiers(session: Session, entity_id: uuid.UUID) -> tuple[Identifier, ...]:
    return tuple(
        session.execute(
            select(Identifier)
            .where(Identifier.entity_id == entity_id, Identifier.deleted_at.is_(None))
            .order_by(Identifier.created_at, Identifier.id)
        ).scalars()
    )


def patch_identifier(
    session: Session,
    keys: VaultKeys,
    identifier_id: uuid.UUID,
    actor_id: uuid.UUID,
    expected_version: int,
    changes: dict[str, object],
    *,
    source_ip: str | None,
) -> Identifier:
    record = session.execute(
        select(Identifier)
        .where(Identifier.id == identifier_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if record is None or record.deleted_at is not None:
        raise DocVaultError("NOT_FOUND")
    if record.row_version != expected_version:
        raise DocVaultError("CONFLICT", detail="The identifier changed. Reload and retry.")

    changed_type = changes.get("id_type", record.id_type)
    if not isinstance(changed_type, str):
        raise DocVaultError("VALIDATION_FAILED", detail="id_type must be a string.")
    id_type = _validate_identifier_type(changed_type)
    current_value = (
        decrypt_column(keys.meta_key, "identifiers", "value_enc", record.value_enc) or ""
    )
    value = changes.get("value", current_value)
    if not isinstance(value, str):
        raise DocVaultError("VALIDATION_FAILED", detail="value must be a non-empty string.")
    value = _required(normalize_identifier(value), "value", maximum=256)
    value_blind = blind_index(keys.bidx_key, id_type, value)
    if "id_type" in changes or "value" in changes:
        _check_identifier_duplicate(
            session,
            id_type=id_type,
            value_blind=value_blind,
            entity_id=record.entity_id,
            duplicate_ack_of=None,
            exclude_id=record.id,
        )
        record.id_type = id_type
        record.value_enc = encrypt_column(keys.meta_key, "identifiers", "value_enc", value) or b""
        record.value_blind = value_blind
    if "label" in changes:
        label = changes["label"]
        if label is not None and not isinstance(label, str):
            raise DocVaultError("VALIDATION_FAILED", detail="label must be a string or null.")
        record.label = _required(label, "label", maximum=100) if label else None
    record.row_version += 1
    session.flush()
    append_event(
        session,
        action="identifier.update",
        object_type="identifier",
        object_id=record.id,
        actor_id=actor_id,
        source_ip=source_ip,
        detail={"fields": sorted(changes)},
    )
    return record


def reveal_identifier(
    session: Session,
    keys: VaultKeys,
    record: Identifier,
    actor_id: uuid.UUID,
    *,
    source_ip: str | None,
) -> dict[str, object]:
    append_event(
        session,
        action="identifier.reveal",
        object_type="identifier",
        object_id=record.id,
        actor_id=actor_id,
        source_ip=source_ip,
        detail={"entity_id": str(record.entity_id), "id_type": record.id_type},
    )
    return identifier_data(record, keys, reveal=True)


def list_persons(
    session: Session, keys: VaultKeys, entity_id: uuid.UUID
) -> tuple[dict[str, object], ...]:
    rows = session.execute(
        select(Person, EntityPerson)
        .join(EntityPerson, EntityPerson.person_id == Person.id)
        .where(EntityPerson.entity_id == entity_id, Person.deleted_at.is_(None))
        .order_by(EntityPerson.role, Person.id)
    )
    return tuple(
        {
            "person_id": person.id,
            "full_name": decrypt_column(
                keys.meta_key, "persons", "full_name_enc", person.full_name_enc
            ),
            "date_of_birth": person.date_of_birth,
            "gender": person.gender,
            "role": link.role,
            "effective_from": link.effective_from,
            "effective_to": link.effective_to,
        }
        for person, link in rows
    )


def add_person(
    session: Session,
    keys: VaultKeys,
    *,
    entity: Entity,
    actor_id: uuid.UUID,
    full_name: str,
    role: PersonRole,
    date_of_birth: date | None,
    gender: Gender | None,
    notes: str | None,
    effective_from: date | None,
    effective_to: date | None,
    source_ip: str | None,
) -> Person:
    if entity.entity_type is EntityType.INDIVIDUAL or role is PersonRole.SELF:
        raise DocVaultError(
            "VALIDATION_FAILED", detail="The self role is managed with the individual entity."
        )
    if effective_from and effective_to and effective_to < effective_from:
        raise DocVaultError(
            "VALIDATION_FAILED", detail="effective_to must not precede effective_from."
        )
    name = _required(full_name, "full_name", maximum=300)
    person = Person(
        full_name_enc=encrypt_column(keys.meta_key, "persons", "full_name_enc", name) or b"",
        name_blind=blind_index(keys.bidx_key, "person_name", name),
        date_of_birth=date_of_birth,
        gender=gender,
        notes_enc=encrypt_column(keys.meta_key, "persons", "notes_enc", notes),
        created_by=actor_id,
    )
    session.add(person)
    session.flush()
    session.add(
        EntityPerson(
            entity_id=entity.id,
            person_id=person.id,
            role=role,
            effective_from=effective_from,
            effective_to=effective_to,
        )
    )
    append_event(
        session,
        action="entity.person.create",
        object_type="entity",
        object_id=entity.id,
        actor_id=actor_id,
        source_ip=source_ip,
        detail={"person_id": str(person.id), "role": role.value},
    )
    return person


def remove_person(
    session: Session,
    entity: Entity,
    person_id: uuid.UUID,
    role: PersonRole,
    actor_id: uuid.UUID,
    *,
    source_ip: str | None,
) -> None:
    if role is PersonRole.SELF and entity.entity_type is EntityType.INDIVIDUAL:
        raise DocVaultError(
            "VALIDATION_FAILED", detail="An individual entity must retain its self person."
        )
    link = session.get(EntityPerson, (entity.id, person_id, role))
    if link is None:
        raise DocVaultError("NOT_FOUND")
    session.delete(link)
    append_event(
        session,
        action="entity.person.remove",
        object_type="entity",
        object_id=entity.id,
        actor_id=actor_id,
        source_ip=source_ip,
        detail={"person_id": str(person_id), "role": role.value},
    )


def entity_timeline(
    session: Session, entity_id: uuid.UUID, *, limit: int = 100
) -> tuple[AuditEvent, ...]:
    return tuple(
        session.execute(
            select(AuditEvent)
            .where(AuditEvent.object_type == "entity", AuditEvent.object_id == entity_id)
            .order_by(AuditEvent.seq.desc())
            .limit(min(max(limit, 1), 200))
        ).scalars()
    )


def entity_count(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(Entity)) or 0)


def lookup_entity(session: Session, entity_id: uuid.UUID) -> Entity | None:
    return session.get(Entity, entity_id)
