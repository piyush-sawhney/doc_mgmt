"""The database contract from docs/04 §10 and docs/13 §11.

These tests use the real PostgreSQL cluster. A mocked database would not prove
that a partial index, a deferred constraint trigger, or a native enum works.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from alembic import command
from sqlalchemy import Connection, create_engine, select, text, update
from sqlalchemy.exc import DBAPIError

from app.db.enums import (
    AclEffect,
    AclObject,
    AclSubject,
    AuditOutcome,
    ConfLevel,
    EntityType,
    PersonRole,
)
from app.db.models import AclEntry, DocType, Document, DocumentVersion, Entity, EntityPerson, User
from tests.integration.conftest import _alembic_config
from tests.integration.factories import (
    blind,
    make_acl,
    make_audit,
    make_company,
    make_doc_type,
    make_document,
    make_group,
    make_individual,
    make_user,
    make_version,
)

EXPECTED_TABLES = {
    "acl_entries",
    "audit_events",
    "doc_types",
    "document_entity_links",
    "document_tags",
    "document_versions",
    "documents",
    "download_tickets",
    "entities",
    "entity_person",
    "group_members",
    "groups",
    "idempotency_keys",
    "identifiers",
    "persons",
    "print_items",
    "print_jobs",
    "renditions",
    "sessions",
    "settings",
    "tags",
    "user_roles",
    "users",
    "version_render_settings",
}


def _sqlstate(excinfo: pytest.ExceptionInfo[DBAPIError]) -> str | None:
    return getattr(excinfo.value.orig, "sqlstate", None)


def test_migration_creates_every_documented_table(connection: Connection) -> None:
    rows = connection.execute(
        text(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_type = 'BASE TABLE' "
            "AND table_name <> 'alembic_version'"
        )
    ).scalars()
    assert set(rows) == EXPECTED_TABLES


def test_migration_downgrades_cleanly(database_url: str) -> None:
    config = _alembic_config(database_url)
    command.downgrade(config, "base")

    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            remaining = set(
                connection.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = 'public' AND table_name <> 'alembic_version'"
                    )
                ).scalars()
            )
    finally:
        engine.dispose()
    assert remaining == set()

    command.upgrade(config, "head")
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            restored = connection.execute(
                text("SELECT to_regclass('public.documents') IS NOT NULL")
            ).scalar_one()
    finally:
        engine.dispose()
    assert restored is True


def test_gender_enum_has_documented_values(connection: Connection) -> None:
    values = connection.execute(
        text(
            "SELECT e.enumlabel FROM pg_enum e "
            "JOIN pg_type t ON t.oid = e.enumtypid "
            "WHERE t.typname = 'gender' ORDER BY e.enumsortorder"
        )
    ).scalars()
    assert set(values) == {"female", "male", "other", "undisclosed"}


def test_capability_print_without_read_is_rejected(connection: Connection) -> None:
    make_user(connection)
    entity = make_company(connection)
    group = make_group(connection, tag=2)
    connection.commit()

    with pytest.raises(DBAPIError) as excinfo:
        make_acl(
            connection,
            object_type=AclObject.ENTITY,
            object_id=entity,
            subject_type=AclSubject.GROUP,
            subject_id=group,
            capabilities=32,
        )
    assert _sqlstate(excinfo) == "23514"
    connection.rollback()


def test_acl_rejects_a_deleted_object(connection: Connection) -> None:
    make_user(connection)
    entity = make_company(connection)
    group = make_group(connection)
    connection.commit()

    connection.execute(
        update(Entity).where(Entity.id == entity).values(deleted_at=datetime.now(UTC))
    )
    connection.commit()

    with pytest.raises(DBAPIError) as excinfo:
        make_acl(
            connection,
            object_type=AclObject.ENTITY,
            object_id=entity,
            subject_type=AclSubject.GROUP,
            subject_id=group,
            capabilities=2,
            effect=AclEffect.DENY,
        )
    assert _sqlstate(excinfo) == "23000"


def test_doc_types_third_level_is_rejected(connection: Connection) -> None:
    category, type_id = make_doc_type(connection)
    connection.commit()
    assert category is not None
    assert type_id is not None

    with pytest.raises(DBAPIError) as excinfo:
        connection.execute(
            DocType.__table__.insert().values(
                id=uuid.uuid7(),
                code="third_level",
                name_enc=b"\x01Third",
                parent_id=type_id,
            )
        )
    assert _sqlstate(excinfo) == "23000"


def test_a_category_with_children_cannot_be_nested(connection: Connection) -> None:
    category, _type_id = make_doc_type(connection)
    other_category, _other_type = make_doc_type(connection, suffix="two")
    connection.commit()

    with pytest.raises(DBAPIError) as excinfo:
        connection.execute(
            update(DocType).where(DocType.id == category).values(parent_id=other_category)
        )
    assert _sqlstate(excinfo) == "23000"


def test_version_count_follows_inserts(connection: Connection) -> None:
    user = make_user(connection)
    _category, doc_type = make_doc_type(connection)
    document = make_document(connection, doc_type_id=doc_type, owner_id=user)
    make_version(connection, document_id=document, uploaded_by=user, version_no=1)
    make_version(connection, document_id=document, uploaded_by=user, version_no=2)
    connection.commit()

    count = connection.execute(
        select(Document.version_count).where(Document.id == document)
    ).scalar_one()
    assert count == 2


def test_current_version_must_belong_to_the_same_document(connection: Connection) -> None:
    user = make_user(connection)
    _category, doc_type = make_doc_type(connection)
    first = make_document(connection, doc_type_id=doc_type, owner_id=user)
    first_version = make_version(connection, document_id=first, uploaded_by=user)
    second = make_document(connection, doc_type_id=doc_type, owner_id=user, tag=2)
    second_version = make_version(connection, document_id=second, uploaded_by=user)
    connection.commit()

    connection.execute(
        update(Document).where(Document.id == first).values(current_version_id=first_version)
    )
    connection.commit()

    with pytest.raises(DBAPIError) as excinfo:
        connection.execute(
            update(Document).where(Document.id == first).values(current_version_id=second_version)
        )
    assert _sqlstate(excinfo) == "23000"


def test_version_content_is_immutable_but_note_is_not(connection: Connection) -> None:
    user = make_user(connection)
    _category, doc_type = make_doc_type(connection)
    document = make_document(connection, doc_type_id=doc_type, owner_id=user)
    version = make_version(connection, document_id=document, uploaded_by=user)
    connection.commit()

    connection.execute(
        update(DocumentVersion)
        .where(DocumentVersion.id == version)
        .values(note_enc=b"\x01Clearer scan")
    )
    connection.commit()

    with pytest.raises(DBAPIError) as excinfo:
        connection.execute(
            update(DocumentVersion).where(DocumentVersion.id == version).values(mime="image/png")
        )
    assert _sqlstate(excinfo) == "23000"


def test_audit_events_are_append_only(connection: Connection) -> None:
    make_audit(connection)
    connection.commit()

    with pytest.raises(DBAPIError) as update_error:
        connection.execute(
            text("UPDATE audit_events SET action = 'tampered' WHERE action = 'test.event'")
        )
    assert _sqlstate(update_error) == "42501"
    connection.rollback()

    with pytest.raises(DBAPIError) as delete_error:
        connection.execute(text("DELETE FROM audit_events WHERE action = 'test.event'"))
    assert _sqlstate(delete_error) == "42501"
    connection.rollback()

    with pytest.raises(DBAPIError) as truncate_error:
        connection.execute(text("TRUNCATE audit_events"))
    assert _sqlstate(truncate_error) == "42501"


def test_legal_hold_blocks_purge(connection: Connection) -> None:
    user = make_user(connection)
    _category, doc_type = make_doc_type(connection)
    document = make_document(connection, doc_type_id=doc_type, owner_id=user, legal_hold=True)
    connection.execute(
        update(Document).where(Document.id == document).values(deleted_at=datetime.now(UTC))
    )
    connection.commit()

    with pytest.raises(DBAPIError) as excinfo:
        connection.execute(
            update(Document).where(Document.id == document).values(purged_at=datetime.now(UTC))
        )
    assert _sqlstate(excinfo) == "23000"


def test_a_document_must_be_deleted_before_purge(connection: Connection) -> None:
    user = make_user(connection)
    _category, doc_type = make_doc_type(connection)
    document = make_document(connection, doc_type_id=doc_type, owner_id=user)
    connection.commit()

    with pytest.raises(DBAPIError) as excinfo:
        connection.execute(
            update(Document).where(Document.id == document).values(purged_at=datetime.now(UTC))
        )
    assert _sqlstate(excinfo) == "23000"


def test_an_individual_needs_exactly_one_self_person(connection: Connection) -> None:
    entity = uuid.uuid7()
    connection.execute(
        Entity.__table__.insert().values(
            id=entity,
            entity_type=EntityType.INDIVIDUAL,
            legal_name_enc=b"\x01Person",
            name_blind=blind(9),
        )
    )
    with pytest.raises(DBAPIError) as excinfo:
        connection.commit()
    assert _sqlstate(excinfo) == "23000"
    connection.rollback()

    make_individual(connection, tag=10)
    connection.commit()


def test_a_company_cannot_have_a_self_person(connection: Connection) -> None:
    _individual, person = make_individual(connection, tag=11)
    company = make_company(connection, tag=12)
    connection.commit()

    connection.execute(
        EntityPerson.__table__.insert().values(
            entity_id=company,
            person_id=person,
            role=PersonRole.SELF,
        )
    )
    with pytest.raises(DBAPIError) as excinfo:
        connection.commit()
    assert _sqlstate(excinfo) == "23000"


def test_updated_at_advances_on_update(connection: Connection) -> None:
    entity = make_company(connection)
    connection.commit()
    before = connection.execute(select(Entity.updated_at).where(Entity.id == entity)).scalar_one()

    connection.execute(
        update(Entity).where(Entity.id == entity).values(legal_name_enc=b"\x01Renamed")
    )
    connection.commit()
    after = connection.execute(select(Entity.updated_at).where(Entity.id == entity)).scalar_one()

    assert after > before


def test_acl_entries_require_a_known_subject(connection: Connection) -> None:
    entity = make_company(connection)
    connection.commit()

    with pytest.raises(DBAPIError) as excinfo:
        make_acl(
            connection,
            object_type=AclObject.ENTITY,
            object_id=entity,
            subject_type=AclSubject.USER,
            subject_id=uuid.uuid7(),
            capabilities=2,
        )
    assert _sqlstate(excinfo) == "23000"


def test_settings_hold_exactly_one_value(connection: Connection) -> None:
    with pytest.raises(DBAPIError) as excinfo:
        connection.execute(
            text("INSERT INTO settings (key, value, value_enc) VALUES ('both', 'plain', :enc)"),
            {"enc": b"\x01cipher"},
        )
    assert _sqlstate(excinfo) == "23514"
    connection.rollback()

    with pytest.raises(DBAPIError) as excinfo:
        connection.execute(text("INSERT INTO settings (key) VALUES ('neither')"))
    assert _sqlstate(excinfo) == "23514"


def test_audit_outcome_enum_is_native(connection: Connection) -> None:
    values = connection.execute(
        text(
            "SELECT e.enumlabel FROM pg_enum e "
            "JOIN pg_type t ON t.oid = e.enumtypid "
            "WHERE t.typname = 'audit_outcome' ORDER BY e.enumsortorder"
        )
    ).scalars()
    assert set(values) == {member.value for member in AuditOutcome}


def test_document_confidentiality_is_stored_as_an_enum(connection: Connection) -> None:
    user = make_user(connection)
    _category, doc_type = make_doc_type(connection)
    document = make_document(connection, doc_type_id=doc_type, owner_id=user)
    connection.commit()

    level = connection.execute(
        text("SELECT confidentiality FROM documents WHERE id = :id"), {"id": document}
    ).scalar_one()
    assert level == ConfLevel.NORMAL.value


def test_partial_indexes_exist(connection: Connection) -> None:
    indexes = connection.execute(
        text(
            "SELECT indexname FROM pg_indexes "
            "WHERE schemaname = 'public' AND indexdef LIKE '%WHERE%'"
        )
    ).scalars()
    names = set(indexes)
    assert {
        "ix_documents_doc_type",
        "ix_documents_expiry",
        "ix_documents_owner",
        "ix_sessions_user_id_live",
        "uq_entity_person_self",
        "ix_identifiers_type_value",
    } <= names


def test_seeded_catalogue_is_visible_through_the_type_tree(seeded, connection: Connection) -> None:
    assert seeded.categories_total == 8
    categories = connection.execute(
        select(DocType.code).where(DocType.parent_id.is_(None)).order_by(DocType.sort_order)
    ).scalars()
    assert list(categories) == [
        "identity",
        "property",
        "legal",
        "corporate",
        "finance",
        "employment",
        "insurance",
        "other",
    ]


def test_acl_capability_masks_are_bounded(connection: Connection) -> None:
    entity = make_company(connection)
    group = make_group(connection)
    connection.commit()

    with pytest.raises(DBAPIError) as excinfo:
        make_acl(
            connection,
            object_type=AclObject.ENTITY,
            object_id=entity,
            subject_type=AclSubject.GROUP,
            subject_id=group,
            capabilities=64,
        )
    assert _sqlstate(excinfo) == "23514"


def test_user_and_acl_rows_are_linked_by_uuid(connection: Connection) -> None:
    user = make_user(connection)
    entity = make_company(connection)
    connection.commit()

    acl = make_acl(
        connection,
        object_type=AclObject.ENTITY,
        object_id=entity,
        subject_type=AclSubject.USER,
        subject_id=user,
        capabilities=3,
    )
    connection.commit()

    subject = connection.execute(select(AclEntry.subject_id).where(AclEntry.id == acl)).scalar_one()
    assert subject == user
    assert connection.execute(select(User.id).where(User.id == user)).scalar_one() == user
