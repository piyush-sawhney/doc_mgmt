from __future__ import annotations

import pytest
from sqlalchemy import create_engine, insert, select, update
from sqlalchemy.orm import Session

from app.core.errors import DocVaultError
from app.db.enums import (
    AclEffect,
    AclMode,
    AclObject,
    AclSubject,
    LinkRole,
    RoleName,
)
from app.db.models.documents import Document, DocumentEntityLink
from app.db.models.entities import Entity
from app.db.models.identity import UserRole
from app.db.models.operations import AuditEvent
from app.services.acl import (
    MANAGE_ACL,
    READ,
    VIEW,
    WRITE,
    Grant,
    replace_acl,
    require_document,
    resolve_access,
    visible_documents,
    visible_entities,
)

from .factories import (
    make_acl,
    make_company,
    make_doc_type,
    make_document,
    make_user,
)


def test_entity_union_denies_and_visible_query(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        user_id = make_user(connection)
        owner_id = make_user(connection, tag=10)
        connection.execute(insert(UserRole).values(user_id=user_id, role=RoleName.READER))
        _, doc_type_id = make_doc_type(connection)
        entity_a = make_company(connection, tag=1)
        entity_b = make_company(connection, tag=2)
        connection.execute(
            update(Entity)
            .where(Entity.id.in_((entity_a, entity_b)))
            .values(acl_mode=AclMode.EXPLICIT)
        )
        allowed_document = make_document(
            connection,
            doc_type_id=doc_type_id,
            owner_id=owner_id,
            tag=1,
        )
        denied_document = make_document(
            connection,
            doc_type_id=doc_type_id,
            owner_id=owner_id,
            tag=2,
        )
        fallback_document = make_document(
            connection,
            doc_type_id=doc_type_id,
            owner_id=owner_id,
            tag=3,
        )
        connection.execute(
            insert(DocumentEntityLink),
            [
                {
                    "document_id": allowed_document,
                    "entity_id": entity_a,
                    "link_role": LinkRole.BELONGS_TO,
                },
                {
                    "document_id": denied_document,
                    "entity_id": entity_a,
                    "link_role": LinkRole.BELONGS_TO,
                },
                {
                    "document_id": denied_document,
                    "entity_id": entity_b,
                    "link_role": LinkRole.PROVES,
                },
            ],
        )
        make_acl(
            connection,
            object_type=AclObject.ENTITY,
            object_id=entity_a,
            subject_type=AclSubject.USER,
            subject_id=user_id,
            capabilities=READ | VIEW,
        )
        make_acl(
            connection,
            object_type=AclObject.ENTITY,
            object_id=entity_b,
            subject_type=AclSubject.USER,
            subject_id=user_id,
            capabilities=VIEW,
            effect=AclEffect.DENY,
        )
    try:
        with Session(engine) as session:
            allowed = session.get(Document, allowed_document)
            denied = session.get(Document, denied_document)
            assert allowed is not None
            assert denied is not None
            assert resolve_access(session, user_id, allowed).capabilities == READ | VIEW
            assert resolve_access(session, user_id, denied).capabilities == 0

            visible_ids = {
                document.id for document in session.scalars(visible_documents(session, user_id))
            }
            assert allowed_document in visible_ids
            assert fallback_document in visible_ids
            assert denied_document not in visible_ids
    finally:
        engine.dispose()


def test_document_acl_replacement_preserves_owner_floor(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        admin_id = make_user(connection, tag=1)
        owner_id = make_user(connection, tag=2)
        reader_id = make_user(connection, tag=3)
        connection.execute(
            insert(UserRole),
            [
                {"user_id": admin_id, "role": RoleName.ADMIN},
                {"user_id": owner_id, "role": RoleName.EDITOR},
                {"user_id": reader_id, "role": RoleName.READER},
            ],
        )
        _, doc_type_id = make_doc_type(connection)
        document_id = make_document(
            connection,
            doc_type_id=doc_type_id,
            owner_id=owner_id,
        )
    try:
        with Session(engine) as session, session.begin():
            saved = replace_acl(
                session,
                object_type=AclObject.DOCUMENT,
                object_id=document_id,
                actor_id=admin_id,
                source_ip="127.0.0.1",
                grants=(
                    Grant(
                        AclSubject.USER,
                        owner_id,
                        VIEW | READ | WRITE | MANAGE_ACL,
                        AclEffect.ALLOW,
                    ),
                    Grant(
                        AclSubject.USER,
                        reader_id,
                        VIEW | READ,
                        AclEffect.ALLOW,
                    ),
                ),
            )
            document = session.get(Document, document_id)
            assert document is not None
            assert document.acl_mode is AclMode.EXPLICIT
            assert len(saved) == 2
            assert resolve_access(session, owner_id, document).capabilities & MANAGE_ACL
            assert resolve_access(session, reader_id, document).capabilities == READ | VIEW

        with pytest.raises(DocVaultError) as error, Session(engine) as session, session.begin():
            replace_acl(
                session,
                object_type=AclObject.DOCUMENT,
                object_id=document_id,
                actor_id=admin_id,
                source_ip="127.0.0.1",
                grants=(
                    Grant(
                        AclSubject.USER,
                        owner_id,
                        VIEW | READ,
                        AclEffect.ALLOW,
                    ),
                ),
            )
        assert error.value.code == "VALIDATION_FAILED"
    finally:
        engine.dispose()


def test_hidden_and_read_denials_are_audited(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        user_id = make_user(connection)
        owner_id = make_user(connection, tag=10)
        connection.execute(insert(UserRole).values(user_id=user_id, role=RoleName.AUDITOR))
        _, doc_type_id = make_doc_type(connection)
        visible_document = make_document(
            connection,
            doc_type_id=doc_type_id,
            owner_id=owner_id,
            tag=1,
        )
        hidden_document = make_document(
            connection,
            doc_type_id=doc_type_id,
            owner_id=owner_id,
            tag=2,
        )
        connection.execute(
            update(Document)
            .where(Document.id.in_((visible_document, hidden_document)))
            .values(acl_mode=AclMode.EXPLICIT)
        )
        make_acl(
            connection,
            object_type=AclObject.DOCUMENT,
            object_id=visible_document,
            subject_type=AclSubject.USER,
            subject_id=user_id,
            capabilities=VIEW,
        )
    try:
        with (
            pytest.raises(DocVaultError) as read_denied,
            Session(engine) as session,
            session.begin(),
        ):
            require_document(
                session,
                user_id,
                visible_document,
                READ,
                source_ip="127.0.0.1",
            )
        assert read_denied.value.code == "FORBIDDEN"
        with (
            pytest.raises(DocVaultError) as hidden,
            Session(engine) as session,
            session.begin(),
        ):
            require_document(
                session,
                user_id,
                hidden_document,
                VIEW,
                source_ip="127.0.0.1",
            )
        assert hidden.value.code == "NOT_FOUND"
        with Session(engine) as session:
            denials = (
                session.execute(select(AuditEvent).where(AuditEvent.action == "access.deny"))
                .scalars()
                .all()
            )
            assert len(denials) == 2
    finally:
        engine.dispose()


def test_visible_entities_applies_explicit_acl_and_role_defaults(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        reader_id = make_user(connection)
        connection.execute(insert(UserRole).values(user_id=reader_id, role=RoleName.READER))
        inherited = make_company(connection, tag=1)
        explicit_allowed = make_company(connection, tag=2)
        explicit_denied = make_company(connection, tag=3)
        connection.execute(
            update(Entity)
            .where(Entity.id.in_((explicit_allowed, explicit_denied)))
            .values(acl_mode=AclMode.EXPLICIT)
        )
        make_acl(
            connection,
            object_type=AclObject.ENTITY,
            object_id=explicit_allowed,
            subject_type=AclSubject.USER,
            subject_id=reader_id,
            capabilities=VIEW,
        )
        make_acl(
            connection,
            object_type=AclObject.ENTITY,
            object_id=explicit_denied,
            subject_type=AclSubject.USER,
            subject_id=reader_id,
            capabilities=VIEW,
            effect=AclEffect.DENY,
        )
    try:
        with Session(engine) as session:
            visible_ids = {
                entity.id for entity in session.scalars(visible_entities(session, reader_id))
            }
        assert inherited in visible_ids
        assert explicit_allowed in visible_ids
        assert explicit_denied not in visible_ids
    finally:
        engine.dispose()
