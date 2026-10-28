"""Small Core-based factories for schema tests.

They deliberately write plain bytes rather than going through the service:
these tests are about the database contract, not about the future service layer.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import Connection, insert

from app.db.enums import (
    AclEffect,
    AclObject,
    AclSubject,
    AuditOutcome,
    ConfLevel,
    EntityType,
    LinkRole,
    PersonRole,
)
from app.db.models import (
    AclEntry,
    AuditEvent,
    DocType,
    Document,
    DocumentEntityLink,
    DocumentVersion,
    Entity,
    EntityPerson,
    Group,
    Person,
    Session,
    User,
)


def blind(tag: int = 1) -> bytes:
    """A 33-byte value with the right shape for a blind index."""
    return bytes(32) + bytes([tag % 256])


def make_user(connection: Connection, *, tag: int = 1) -> uuid.UUID:
    user_id = uuid.uuid7()
    connection.execute(
        insert(User).values(
            id=user_id,
            username_enc=b"\x01user",
            username_blind=blind(tag),
            display_name_enc=b"\x01User",
            password_hash="$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$hash",
        )
    )
    return user_id


def make_group(connection: Connection, *, tag: int = 1) -> uuid.UUID:
    group_id = uuid.uuid7()
    connection.execute(insert(Group).values(id=group_id, name=f"Group {tag}"))
    return group_id


def make_company(connection: Connection, *, tag: int = 1) -> uuid.UUID:
    entity_id = uuid.uuid7()
    connection.execute(
        insert(Entity).values(
            id=entity_id,
            entity_type=EntityType.COMPANY,
            legal_name_enc=b"\x01Company",
            name_blind=blind(tag),
        )
    )
    return entity_id


def make_person(connection: Connection, *, tag: int = 1) -> uuid.UUID:
    person_id = uuid.uuid7()
    connection.execute(
        insert(Person).values(
            id=person_id,
            full_name_enc=b"\x01Person",
            name_blind=blind(tag),
        )
    )
    return person_id


def make_individual(connection: Connection, *, tag: int = 1) -> tuple[uuid.UUID, uuid.UUID]:
    """Create an individual and its mandatory self link in one transaction."""
    entity_id = uuid.uuid7()
    person_id = make_person(connection, tag=tag)
    connection.execute(
        insert(Entity).values(
            id=entity_id,
            entity_type=EntityType.INDIVIDUAL,
            legal_name_enc=b"\x01Person",
            name_blind=blind(tag),
        )
    )
    connection.execute(
        insert(EntityPerson).values(
            entity_id=entity_id,
            person_id=person_id,
            role=PersonRole.SELF,
        )
    )
    return entity_id, person_id


def make_doc_type(connection: Connection, *, suffix: str = "one") -> tuple[uuid.UUID, uuid.UUID]:
    category_id = uuid.uuid7()
    type_id = uuid.uuid7()
    connection.execute(
        insert(DocType).values(
            id=category_id,
            code=f"category_{suffix}",
            name_enc=b"\x01Category",
            parent_id=None,
        )
    )
    connection.execute(
        insert(DocType).values(
            id=type_id,
            code=f"type_{suffix}",
            name_enc=b"\x01Type",
            parent_id=category_id,
            default_confidentiality=ConfLevel.NORMAL,
        )
    )
    return category_id, type_id


def make_document(
    connection: Connection,
    *,
    doc_type_id: uuid.UUID,
    owner_id: uuid.UUID,
    tag: int = 1,
    legal_hold: bool = False,
) -> uuid.UUID:
    document_id = uuid.uuid7()
    connection.execute(
        insert(Document).values(
            id=document_id,
            doc_type_id=doc_type_id,
            title_enc=b"\x01Title",
            owner_id=owner_id,
            confidentiality=ConfLevel.NORMAL,
            legal_hold=legal_hold,
        )
    )
    return document_id


def make_version(
    connection: Connection,
    *,
    document_id: uuid.UUID,
    uploaded_by: uuid.UUID,
    version_no: int = 1,
) -> uuid.UUID:
    version_id = uuid.uuid7()
    connection.execute(
        insert(DocumentVersion).values(
            id=version_id,
            document_id=document_id,
            version_no=version_no,
            blob_addr=secrets.token_hex(32),
            blob_salt=secrets.token_bytes(16),
            plaintext_size=10,
            stored_size=4096,
            mime="application/pdf",
            original_filename_enc=b"\x01file.pdf",
            uploaded_by=uploaded_by,
        )
    )
    return version_id


def make_acl(
    connection: Connection,
    *,
    object_type: AclObject,
    object_id: uuid.UUID,
    subject_type: AclSubject,
    subject_id: uuid.UUID,
    capabilities: int,
    effect: AclEffect = AclEffect.ALLOW,
) -> uuid.UUID:
    acl_id = uuid.uuid7()
    connection.execute(
        insert(AclEntry).values(
            id=acl_id,
            object_type=object_type,
            object_id=object_id,
            subject_type=subject_type,
            subject_id=subject_id,
            capabilities=capabilities,
            effect=effect,
        )
    )
    return acl_id


def make_audit(connection: Connection) -> int:
    seq = connection.execute(
        insert(AuditEvent)
        .values(
            actor_id=None,
            action="test.event",
            object_type="test",
            object_id=None,
            outcome=AuditOutcome.ALLOW,
            detail={},
            prev_hash=bytes(32),
            hash=bytes(32),
            file_month="2026-10",
        )
        .returning(AuditEvent.seq)
    ).scalar_one()
    return int(seq)


def make_session(connection: Connection, *, user_id: uuid.UUID, revoked: bool = False) -> uuid.UUID:
    session_id = uuid.uuid7()
    now = datetime.now(UTC)
    connection.execute(
        insert(Session).values(
            id=session_id,
            user_id=user_id,
            token_hash=secrets.token_bytes(32),
            csrf_secret=secrets.token_bytes(32),
            idle_expires_at=now + timedelta(minutes=30),
            absolute_expires_at=now + timedelta(hours=12),
            source_ip="127.0.0.1",
            user_agent="pytest",
            revoked_at=now if revoked else None,
        )
    )
    return session_id


def make_link(
    connection: Connection,
    *,
    document_id: uuid.UUID,
    entity_id: uuid.UUID,
    role: LinkRole = LinkRole.BELONGS_TO,
) -> None:
    connection.execute(
        insert(DocumentEntityLink).values(
            document_id=document_id,
            entity_id=entity_id,
            link_role=role,
        )
    )
