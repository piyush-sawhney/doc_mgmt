"""The ACL matrix from ``docs/06`` §5 and §10, at the resolver boundary.

These tests exercise the single gate the routes call. Each case is a row of the
documented matrix: closure, deny-wins, group membership, restricted printing,
break-glass, and the escalation rules that stop a document owner from handing
out more than they hold.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, func, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import DocVaultError
from app.db.enums import (
    AclEffect,
    AclMode,
    AclObject,
    AclSubject,
    ConfLevel,
    LinkRole,
    RoleName,
)
from app.db.models.documents import Document, DocumentEntityLink
from app.db.models.entities import Entity
from app.db.models.identity import GroupMember, UserRole
from app.db.models.operations import AuditEvent
from app.services.acl import (
    ALL,
    MANAGE_ACL,
    OWNER_FLOOR,
    PRINT,
    READ,
    VIEW,
    WRITE,
    Grant,
    replace_acl,
    require_document,
    resolve_access,
    visible_documents,
)

from .factories import (
    make_acl,
    make_company,
    make_doc_type,
    make_document,
    make_group,
    make_user,
)


def _link(connection, document_id: uuid.UUID, entity_id: uuid.UUID) -> None:
    connection.execute(
        insert(DocumentEntityLink).values(
            document_id=document_id,
            entity_id=entity_id,
            link_role=LinkRole.BELONGS_TO,
        )
    )


def _explicit(connection, entity_id: uuid.UUID) -> None:
    connection.execute(
        update(Entity).where(Entity.id == entity_id).values(acl_mode=AclMode.EXPLICIT)
    )


@pytest.fixture
def graph(database_url: str):
    """A small office: roles, two groups, one entity, one linked document."""
    engine = create_engine(database_url)
    with engine.begin() as connection:
        reader = make_user(connection, tag=1)
        owner = make_user(connection, tag=2)
        connection.execute(
            insert(UserRole),
            [
                {"user_id": reader, "role": RoleName.READER},
                {"user_id": owner, "role": RoleName.EDITOR},
            ],
        )
        finance = make_group(connection, tag=1)
        contractors = make_group(connection, tag=2)
        connection.execute(
            insert(GroupMember),
            [
                {"group_id": finance, "user_id": reader},
                {"group_id": contractors, "user_id": reader},
            ],
        )
        entity = make_company(connection, tag=1)
        _explicit(connection, entity)
        _, doc_type = make_doc_type(connection)
        document = make_document(connection, doc_type_id=doc_type, owner_id=owner, tag=1)
        _link(connection, document, entity)
    try:
        yield {
            "engine": engine,
            "reader": reader,
            "owner": owner,
            "finance": finance,
            "contractors": contractors,
            "entity": entity,
            "document": document,
        }
    finally:
        engine.dispose()


def _add(group, **kwargs) -> None:
    with group["engine"].begin() as connection:
        make_acl(
            connection,
            object_type=AclObject.ENTITY,
            object_id=group["entity"],
            **kwargs,
        )


def test_group_allow_and_group_deny_resolve_to_nothing(graph) -> None:
    _add(
        graph,
        subject_type=AclSubject.GROUP,
        subject_id=graph["finance"],
        capabilities=VIEW | READ,
    )
    _add(
        graph,
        subject_type=AclSubject.GROUP,
        subject_id=graph["contractors"],
        capabilities=VIEW | READ | WRITE,
        effect=AclEffect.DENY,
    )

    with Session(graph["engine"]) as session:
        document = session.get(Document, graph["document"])
        assert document is not None
        assert resolve_access(session, graph["reader"], document).capabilities == 0


def test_removing_group_membership_takes_effect_immediately(graph) -> None:
    _add(
        graph,
        subject_type=AclSubject.GROUP,
        subject_id=graph["finance"],
        capabilities=VIEW | READ,
    )
    _add(
        graph,
        subject_type=AclSubject.GROUP,
        subject_id=graph["contractors"],
        capabilities=VIEW,
        effect=AclEffect.DENY,
    )

    with Session(graph["engine"]) as session:
        document = session.get(Document, graph["document"])
        assert document is not None
        assert resolve_access(session, graph["reader"], document).capabilities == 0

    with graph["engine"].begin() as connection:
        connection.execute(
            GroupMember.__table__.delete().where(
                GroupMember.group_id == graph["contractors"],
                GroupMember.user_id == graph["reader"],
            )
        )

    with Session(graph["engine"]) as session:
        document = session.get(Document, graph["document"])
        assert document is not None
        assert resolve_access(session, graph["reader"], document).capabilities == READ | VIEW


def test_the_database_rejects_an_unclosed_grant(graph) -> None:
    # Read implies view and print implies read are enforced twice: by the
    # resolver's close_up and by a check constraint on the stored row.
    with pytest.raises(IntegrityError):
        _add(
            graph,
            subject_type=AclSubject.USER,
            subject_id=graph["reader"],
            capabilities=READ,
        )


@pytest.mark.parametrize(
    ("allowed", "denied", "expected"),
    [
        pytest.param(VIEW | READ, VIEW, 0, id="deny-view-removes-read-and-print"),
        pytest.param(
            VIEW | READ | PRINT,
            VIEW | READ,
            0,
            id="deny-read-removes-print",
        ),
        pytest.param(
            VIEW | READ | PRINT,
            WRITE,
            VIEW | READ | PRINT,
            id="unrelated-deny-does-nothing",
        ),
    ],
)
def test_denials_close_downward(graph, allowed: int, denied: int, expected: int) -> None:
    # One row per subject, so the deny arrives through a group the reader is
    # in. Deny-wins still applies across subjects (docs/06 §5).
    _add(
        graph,
        subject_type=AclSubject.USER,
        subject_id=graph["reader"],
        capabilities=allowed,
    )
    _add(
        graph,
        subject_type=AclSubject.GROUP,
        subject_id=graph["contractors"],
        capabilities=denied,
        effect=AclEffect.DENY,
    )
    with Session(graph["engine"]) as session:
        document = session.get(Document, graph["document"])
        assert document is not None
        assert resolve_access(session, graph["reader"], document).capabilities == expected


def test_a_second_linked_entitys_deny_wins_over_the_first_entitys_allow(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        reader = make_user(connection)
        connection.execute(insert(UserRole).values(user_id=reader, role=RoleName.READER))
        owner = make_user(connection, tag=2)
        first = make_company(connection, tag=1)
        second = make_company(connection, tag=2)
        _explicit(connection, first)
        _explicit(connection, second)
        _, doc_type = make_doc_type(connection)
        document_id = make_document(connection, doc_type_id=doc_type, owner_id=owner)
        _link(connection, document_id, first)
        _link(connection, document_id, second)
        make_acl(
            connection,
            object_type=AclObject.ENTITY,
            object_id=first,
            subject_type=AclSubject.USER,
            subject_id=reader,
            capabilities=VIEW | READ,
        )
        make_acl(
            connection,
            object_type=AclObject.ENTITY,
            object_id=second,
            subject_type=AclSubject.USER,
            subject_id=reader,
            capabilities=VIEW,
            effect=AclEffect.DENY,
        )
    try:
        with Session(engine) as session:
            document = session.get(Document, document_id)
            assert document is not None
            assert resolve_access(session, reader, document).capabilities == 0
    finally:
        engine.dispose()


def test_the_owner_floor_survives_an_entity_deny(graph) -> None:
    _add(
        graph,
        subject_type=AclSubject.USER,
        subject_id=graph["owner"],
        capabilities=VIEW,
        effect=AclEffect.DENY,
    )
    with Session(graph["engine"]) as session:
        document = session.get(Document, graph["document"])
        assert document is not None
        assert resolve_access(session, graph["owner"], document).capabilities == OWNER_FLOOR


def test_restricted_print_needs_an_explicit_document_grant(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        reader = make_user(connection)
        connection.execute(insert(UserRole).values(user_id=reader, role=RoleName.READER))
        owner = make_user(connection, tag=2)
        _, doc_type = make_doc_type(connection)
        document_id = make_document(connection, doc_type_id=doc_type, owner_id=owner)
        connection.execute(
            update(Document)
            .where(Document.id == document_id)
            .values(confidentiality=ConfLevel.RESTRICTED)
        )
    try:
        with (
            pytest.raises(DocVaultError) as denied,
            Session(engine) as session,
            session.begin(),
        ):
            require_document(
                session,
                reader,
                document_id,
                PRINT,
                source_ip="127.0.0.1",
            )
        assert denied.value.code == "PRINT_RESTRICTED"

        with engine.begin() as connection:
            connection.execute(
                update(Document).where(Document.id == document_id).values(acl_mode=AclMode.EXPLICIT)
            )
            make_acl(
                connection,
                object_type=AclObject.DOCUMENT,
                object_id=document_id,
                subject_type=AclSubject.USER,
                subject_id=reader,
                capabilities=VIEW | READ | PRINT,
            )

        with Session(engine) as session, session.begin():
            document = require_document(
                session,
                reader,
                document_id,
                PRINT,
                source_ip="127.0.0.1",
            )
            assert document.id == document_id
    finally:
        engine.dispose()


def test_an_admin_prints_a_restricted_document_without_a_grant(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        admin = make_user(connection)
        connection.execute(insert(UserRole).values(user_id=admin, role=RoleName.ADMIN))
        owner = make_user(connection, tag=2)
        _, doc_type = make_doc_type(connection)
        document_id = make_document(connection, doc_type_id=doc_type, owner_id=owner)
        connection.execute(
            update(Document)
            .where(Document.id == document_id)
            .values(confidentiality=ConfLevel.RESTRICTED)
        )
    try:
        with Session(engine) as session, session.begin():
            assert (
                require_document(session, admin, document_id, PRINT, source_ip="127.0.0.1").id
                == document_id
            )
    finally:
        engine.dispose()


def test_break_glass_read_needs_a_reason_and_is_audited(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        admin = make_user(connection)
        connection.execute(insert(UserRole).values(user_id=admin, role=RoleName.ADMIN))
        owner = make_user(connection, tag=2)
        _, doc_type = make_doc_type(connection)
        document_id = make_document(connection, doc_type_id=doc_type, owner_id=owner)
    try:
        with (
            pytest.raises(DocVaultError) as denied,
            Session(engine) as session,
            session.begin(),
        ):
            require_document(session, admin, document_id, READ, source_ip="127.0.0.1")
        assert denied.value.code == "VALIDATION_FAILED"

        with Session(engine) as session, session.begin():
            require_document(
                session,
                admin,
                document_id,
                READ,
                source_ip="127.0.0.1",
                break_glass_reason="Auditor asked for the signed agreement",
            )

        with Session(engine) as session:
            event = session.execute(
                select(AuditEvent).where(AuditEvent.action == "document.breakglass_read")
            ).scalar_one()
            assert event.detail["reason"] == "Auditor asked for the signed agreement"
            assert event.actor_id == admin
    finally:
        engine.dispose()


def test_an_auditor_sees_a_document_but_cannot_download_it(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        auditor = make_user(connection)
        connection.execute(insert(UserRole).values(user_id=auditor, role=RoleName.AUDITOR))
        owner = make_user(connection, tag=2)
        _, doc_type = make_doc_type(connection)
        document_id = make_document(connection, doc_type_id=doc_type, owner_id=owner)
    try:
        with Session(engine) as session:
            document = session.get(Document, document_id)
            assert document is not None
            assert resolve_access(session, auditor, document).capabilities == VIEW

        with (
            pytest.raises(DocVaultError) as denied,
            Session(engine) as session,
            session.begin(),
        ):
            require_document(session, auditor, document_id, READ, source_ip="127.0.0.1")
        assert denied.value.code == "FORBIDDEN"
        assert "read" in denied.value.detail

        with Session(engine) as session:
            denial = session.execute(
                select(AuditEvent).where(AuditEvent.action == "access.deny")
            ).scalar_one()
            assert denial.detail["capability"] == READ
    finally:
        engine.dispose()


def test_a_soft_deleted_document_is_hidden_except_from_an_admin(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        admin = make_user(connection)
        reader = make_user(connection, tag=2)
        connection.execute(
            insert(UserRole),
            [
                {"user_id": admin, "role": RoleName.ADMIN},
                {"user_id": reader, "role": RoleName.READER},
            ],
        )
        owner = make_user(connection, tag=3)
        _, doc_type = make_doc_type(connection)
        document_id = make_document(connection, doc_type_id=doc_type, owner_id=owner)
        connection.execute(
            update(Document).where(Document.id == document_id).values(deleted_at=datetime.now(UTC))
        )
    try:
        with (
            pytest.raises(DocVaultError) as hidden,
            Session(engine) as session,
            session.begin(),
        ):
            require_document(session, reader, document_id, VIEW, source_ip="127.0.0.1")
        assert hidden.value.code == "NOT_FOUND"

        with Session(engine) as session, session.begin():
            assert (
                require_document(
                    session,
                    admin,
                    document_id,
                    VIEW,
                    source_ip="127.0.0.1",
                    include_deleted=True,
                ).id
                == document_id
            )
    finally:
        engine.dispose()


def test_visible_documents_counts_only_what_the_user_may_see(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        reader = make_user(connection)
        connection.execute(insert(UserRole).values(user_id=reader, role=RoleName.READER))
        owner = make_user(connection, tag=2)
        _, doc_type = make_doc_type(connection)
        inherited = make_document(connection, doc_type_id=doc_type, owner_id=owner, tag=1)
        allowed = make_document(connection, doc_type_id=doc_type, owner_id=owner, tag=2)
        readonly = make_document(connection, doc_type_id=doc_type, owner_id=owner, tag=3)
        denied = make_document(connection, doc_type_id=doc_type, owner_id=owner, tag=4)
        for document_id in (allowed, readonly, denied):
            connection.execute(
                update(Document).where(Document.id == document_id).values(acl_mode=AclMode.EXPLICIT)
            )
        make_acl(
            connection,
            object_type=AclObject.DOCUMENT,
            object_id=allowed,
            subject_type=AclSubject.USER,
            subject_id=reader,
            capabilities=VIEW | READ,
        )
        make_acl(
            connection,
            object_type=AclObject.DOCUMENT,
            object_id=readonly,
            subject_type=AclSubject.USER,
            subject_id=reader,
            capabilities=VIEW,
        )
        make_acl(
            connection,
            object_type=AclObject.DOCUMENT,
            object_id=denied,
            subject_type=AclSubject.USER,
            subject_id=reader,
            capabilities=VIEW,
            effect=AclEffect.DENY,
        )
    try:
        with Session(engine) as session:
            visible = {
                document.id for document in session.scalars(visible_documents(session, reader))
            }
            readable = {
                document.id
                for document in session.scalars(visible_documents(session, reader, capability=READ))
            }
            count = session.scalar(
                select(func.count()).select_from(visible_documents(session, reader).subquery())
            )
        assert visible == {inherited, allowed, readonly}
        assert readable == {inherited, allowed}
        assert count == 3
    finally:
        engine.dispose()


def test_an_editor_cannot_manage_an_entity_acl(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        editor = make_user(connection)
        connection.execute(insert(UserRole).values(user_id=editor, role=RoleName.EDITOR))
        entity = make_company(connection)
    try:
        with (
            pytest.raises(DocVaultError) as denied,
            Session(engine) as session,
            session.begin(),
        ):
            replace_acl(
                session,
                object_type=AclObject.ENTITY,
                object_id=entity,
                actor_id=editor,
                source_ip="127.0.0.1",
                grants=(Grant(AclSubject.USER, editor, VIEW, AclEffect.ALLOW),),
            )
        assert denied.value.code == "FORBIDDEN"
    finally:
        engine.dispose()


def _managed_document(connection, *, actor: uuid.UUID, owner: uuid.UUID) -> uuid.UUID:
    _, doc_type = make_doc_type(connection, suffix="managed")
    document_id = make_document(connection, doc_type_id=doc_type, owner_id=owner)
    connection.execute(
        update(Document).where(Document.id == document_id).values(acl_mode=AclMode.EXPLICIT)
    )
    make_acl(
        connection,
        object_type=AclObject.DOCUMENT,
        object_id=document_id,
        subject_type=AclSubject.USER,
        subject_id=owner,
        capabilities=OWNER_FLOOR,
    )
    make_acl(
        connection,
        object_type=AclObject.DOCUMENT,
        object_id=document_id,
        subject_type=AclSubject.USER,
        subject_id=actor,
        capabilities=VIEW | READ | WRITE | MANAGE_ACL,
    )
    return document_id


def test_a_delegate_cannot_grant_to_themselves(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        delegate = make_user(connection)
        owner = make_user(connection, tag=2)
        document_id = _managed_document(connection, actor=delegate, owner=owner)
    try:
        with (
            pytest.raises(DocVaultError) as denied,
            Session(engine) as session,
            session.begin(),
        ):
            replace_acl(
                session,
                object_type=AclObject.DOCUMENT,
                object_id=document_id,
                actor_id=delegate,
                source_ip="127.0.0.1",
                grants=(
                    Grant(AclSubject.USER, owner, OWNER_FLOOR, AclEffect.ALLOW),
                    Grant(AclSubject.USER, delegate, VIEW | READ | WRITE, AclEffect.ALLOW),
                ),
            )
        assert denied.value.code == "VALIDATION_FAILED"
        assert "yourself" in denied.value.detail
    finally:
        engine.dispose()


def test_a_delegate_cannot_hand_out_a_capability_they_do_not_hold(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        delegate = make_user(connection)
        owner = make_user(connection, tag=2)
        other = make_user(connection, tag=3)
        document_id = _managed_document(connection, actor=delegate, owner=owner)
    try:
        with (
            pytest.raises(DocVaultError) as denied,
            Session(engine) as session,
            session.begin(),
        ):
            replace_acl(
                session,
                object_type=AclObject.DOCUMENT,
                object_id=document_id,
                actor_id=delegate,
                source_ip="127.0.0.1",
                grants=(
                    Grant(AclSubject.USER, owner, OWNER_FLOOR, AclEffect.ALLOW),
                    Grant(
                        AclSubject.USER,
                        delegate,
                        VIEW | READ | WRITE | MANAGE_ACL,
                        AclEffect.ALLOW,
                    ),
                    Grant(AclSubject.USER, other, PRINT, AclEffect.ALLOW),
                ),
            )
        assert denied.value.code == "FORBIDDEN"
        assert "capabilities you do not hold" in denied.value.detail
    finally:
        engine.dispose()


def test_a_non_owner_cannot_grant_manage_acl(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        delegate = make_user(connection)
        owner = make_user(connection, tag=2)
        other = make_user(connection, tag=3)
        document_id = _managed_document(connection, actor=delegate, owner=owner)
    try:
        with (
            pytest.raises(DocVaultError) as denied,
            Session(engine) as session,
            session.begin(),
        ):
            replace_acl(
                session,
                object_type=AclObject.DOCUMENT,
                object_id=document_id,
                actor_id=delegate,
                source_ip="127.0.0.1",
                grants=(
                    Grant(AclSubject.USER, owner, OWNER_FLOOR, AclEffect.ALLOW),
                    Grant(
                        AclSubject.USER,
                        delegate,
                        VIEW | READ | WRITE | MANAGE_ACL,
                        AclEffect.ALLOW,
                    ),
                    Grant(AclSubject.USER, other, VIEW | MANAGE_ACL, AclEffect.ALLOW),
                ),
            )
        assert denied.value.code == "FORBIDDEN"
        assert "owner or an administrator" in denied.value.detail
    finally:
        engine.dispose()


def test_only_an_admin_can_add_a_deny(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        delegate = make_user(connection)
        owner = make_user(connection, tag=2)
        other = make_user(connection, tag=3)
        document_id = _managed_document(connection, actor=delegate, owner=owner)
    try:
        with (
            pytest.raises(DocVaultError) as denied,
            Session(engine) as session,
            session.begin(),
        ):
            replace_acl(
                session,
                object_type=AclObject.DOCUMENT,
                object_id=document_id,
                actor_id=delegate,
                source_ip="127.0.0.1",
                grants=(
                    Grant(AclSubject.USER, owner, OWNER_FLOOR, AclEffect.ALLOW),
                    Grant(
                        AclSubject.USER,
                        delegate,
                        VIEW | READ | WRITE | MANAGE_ACL,
                        AclEffect.ALLOW,
                    ),
                    Grant(AclSubject.USER, other, VIEW, AclEffect.DENY),
                ),
            )
        assert denied.value.code == "FORBIDDEN"
        assert "deny" in denied.value.detail
    finally:
        engine.dispose()


def test_a_successful_replacement_is_audited_with_before_and_after(database_url: str) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        admin = make_user(connection)
        connection.execute(insert(UserRole).values(user_id=admin, role=RoleName.ADMIN))
        owner = make_user(connection, tag=2)
        reader = make_user(connection, tag=3)
        _, doc_type = make_doc_type(connection)
        document_id = make_document(connection, doc_type_id=doc_type, owner_id=owner)
    try:
        with Session(engine) as session, session.begin():
            replace_acl(
                session,
                object_type=AclObject.DOCUMENT,
                object_id=document_id,
                actor_id=admin,
                source_ip="127.0.0.1",
                grants=(
                    Grant(AclSubject.USER, owner, OWNER_FLOOR, AclEffect.ALLOW),
                    Grant(AclSubject.USER, reader, VIEW | READ, AclEffect.ALLOW),
                ),
            )

        with Session(engine) as session:
            event = session.execute(
                select(AuditEvent).where(AuditEvent.action == "document.acl_changed")
            ).scalar_one()
            assert event.detail["before"] == []
            after = {item["subject_id"]: item for item in event.detail["after"]}
            assert after[str(reader)]["capabilities"] == VIEW | READ
            assert after[str(owner)]["capabilities"] == OWNER_FLOOR
            assert ALL >= after[str(owner)]["capabilities"] > 0
    finally:
        engine.dispose()
