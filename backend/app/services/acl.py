"""Single permission resolver for documents and linked entities."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Final

from sqlalchemy import Select, and_, case, delete, func, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from app.core.errors import DocVaultError
from app.db.enums import (
    AclEffect,
    AclMode,
    AclObject,
    AclSubject,
    ConfLevel,
    RoleName,
)
from app.db.models.documents import Document, DocumentEntityLink
from app.db.models.entities import Entity
from app.db.models.identity import Group, GroupMember, User, UserRole
from app.db.models.operations import AclEntry
from app.services.audit import append_event

VIEW: Final = 1
READ: Final = 2
WRITE: Final = 4
DELETE: Final = 8
MANAGE_ACL: Final = 16
PRINT: Final = 32
ALL: Final = 63
OWNER_FLOOR: Final = VIEW | READ | WRITE | MANAGE_ACL
CAPABILITY_BITS: Final[dict[str, int]] = {
    "view": VIEW,
    "read": READ,
    "write": WRITE,
    "delete": DELETE,
    "manage_acl": MANAGE_ACL,
    "print": PRINT,
}

_ROLE_CAPABILITIES: Final[dict[RoleName, int]] = {
    RoleName.EDITOR: VIEW | READ | WRITE | DELETE | PRINT,
    RoleName.READER: VIEW | READ | PRINT,
    RoleName.AUDITOR: VIEW,
}


@dataclass(frozen=True, slots=True)
class Access:
    """Resolved document permissions and the scope that supplied them."""

    capabilities: int
    explicit_document_capabilities: int
    scope: str


@dataclass(frozen=True, slots=True)
class Grant:
    """Validated ACL entry payload."""

    subject_type: AclSubject
    subject_id: uuid.UUID
    capabilities: int
    effect: AclEffect


def close_up(capabilities: int) -> int:
    """Apply capability implications to grants."""
    if capabilities & PRINT:
        capabilities |= READ | VIEW
    if capabilities & READ:
        capabilities |= VIEW
    return capabilities


def close_down(capabilities: int) -> int:
    """Apply capability implications to denials."""
    if capabilities & VIEW:
        capabilities |= READ | PRINT
    elif capabilities & READ:
        capabilities |= PRINT
    return capabilities


def _role_capabilities(session: Session, user_id: uuid.UUID) -> int:
    roles = session.execute(select(UserRole.role).where(UserRole.user_id == user_id)).scalars()
    capabilities = 0
    for role in roles:
        if role is RoleName.ADMIN:
            return ALL
        capabilities |= _ROLE_CAPABILITIES[role]
    return close_up(capabilities)


def _subjects(session: Session, user_id: uuid.UUID) -> tuple[uuid.UUID, ...]:
    groups = session.execute(
        select(GroupMember.group_id).where(GroupMember.user_id == user_id)
    ).scalars()
    return (user_id, *groups)


def _explicit_entity_ids(session: Session, document_id: uuid.UUID) -> tuple[uuid.UUID, ...]:
    entity_ids = tuple(
        session.execute(
            select(DocumentEntityLink.entity_id).where(
                DocumentEntityLink.document_id == document_id
            )
        ).scalars()
    )
    if not entity_ids:
        return ()
    return tuple(
        session.execute(
            select(AclEntry.object_id)
            .join(Entity, Entity.id == AclEntry.object_id)
            .where(
                AclEntry.object_type == AclObject.ENTITY,
                AclEntry.object_id.in_(entity_ids),
                Entity.acl_mode == AclMode.EXPLICIT,
            )
            .distinct()
        ).scalars()
    )


def resolve_access(session: Session, user_id: uuid.UUID, document: Document) -> Access:
    """Resolve document grants using document, explicit-entity, then role scope."""
    role_caps = _role_capabilities(session, user_id)
    if role_caps == ALL:
        return Access(ALL, ALL, "admin")

    subjects = _subjects(session, user_id)
    subject_filter = _subject_predicate(user_id, subjects[1:])

    if document.acl_mode is AclMode.EXPLICIT:
        scopes = [(AclObject.DOCUMENT, document.id)]
        scope_name = "document"
    else:
        explicit_entity_ids = _explicit_entity_ids(session, document.id)
        if explicit_entity_ids:
            scopes = [(AclObject.ENTITY, entity_id) for entity_id in explicit_entity_ids]
            scope_name = "entity"
        else:
            return Access(
                role_caps | (OWNER_FLOOR if document.owner_id == user_id else 0),
                0,
                "role",
            )

    entries = session.execute(
        select(AclEntry).where(
            AclEntry.object_type.in_([object_type for object_type, _ in scopes]),
            AclEntry.object_id.in_([object_id for _, object_id in scopes]),
            subject_filter,
        )
    ).scalars()
    allowed = 0
    denied = 0
    explicit_document_allowed = 0
    for entry in entries:
        if entry.effect is AclEffect.ALLOW:
            allowed |= entry.capabilities
            if entry.object_type is AclObject.DOCUMENT:
                explicit_document_allowed |= entry.capabilities
        else:
            denied |= entry.capabilities
    capabilities = close_up(allowed) & ~close_down(denied)
    if document.owner_id == user_id:
        capabilities |= OWNER_FLOOR
    return Access(capabilities, close_up(explicit_document_allowed), scope_name)


def resolve_entity_access(session: Session, user_id: uuid.UUID, entity: Entity) -> Access:
    """Resolve entity grants using explicit ACLs or the vault role defaults."""
    role_caps = _role_capabilities(session, user_id)
    if role_caps == ALL:
        return Access(ALL, ALL, "admin")
    if entity.acl_mode is AclMode.INHERIT:
        return Access(role_caps, 0, "role")

    subjects = _subjects(session, user_id)
    subject_filter = and_(
        AclEntry.subject_type == AclSubject.USER,
        AclEntry.subject_id == user_id,
    )
    if len(subjects) > 1:
        subject_filter = or_(
            subject_filter,
            and_(
                AclEntry.subject_type == AclSubject.GROUP,
                AclEntry.subject_id.in_(subjects[1:]),
            ),
        )
    entries = session.execute(
        select(AclEntry).where(
            AclEntry.object_type == AclObject.ENTITY,
            AclEntry.object_id == entity.id,
            subject_filter,
        )
    ).scalars()
    allowed = 0
    denied = 0
    for entry in entries:
        if entry.effect is AclEffect.ALLOW:
            allowed |= entry.capabilities
        else:
            denied |= entry.capabilities
    return Access(close_up(allowed) & ~close_down(denied), 0, "entity")


def _audit_denial(
    session: Session,
    *,
    user_id: uuid.UUID,
    document_id: uuid.UUID,
    source_ip: str | None,
    capability: int,
) -> None:
    """Persist denial evidence separately so the rejected request can roll back."""
    bind = session.get_bind()
    with Session(bind=bind) as audit_session, audit_session.begin():
        append_event(
            audit_session,
            action="access.deny",
            object_type="document",
            object_id=document_id,
            actor_id=user_id,
            outcome="deny",
            source_ip=source_ip,
            detail={"capability": capability},
        )


def require_document(
    session: Session,
    user_id: uuid.UUID,
    document_id: uuid.UUID,
    capability: int,
    *,
    source_ip: str | None = None,
    break_glass_reason: str | None = None,
    include_deleted: bool = False,
) -> Document:
    """Require one document capability, hiding documents without ``view``."""
    document = session.get(Document, document_id)
    if document is None:
        _audit_denial(
            session,
            user_id=user_id,
            document_id=document_id,
            source_ip=source_ip,
            capability=capability,
        )
        raise DocVaultError("NOT_FOUND")

    access = resolve_access(session, user_id, document)
    if document.deleted_at is not None and not include_deleted:
        _audit_denial(
            session,
            user_id=user_id,
            document_id=document_id,
            source_ip=source_ip,
            capability=capability,
        )
        raise DocVaultError("NOT_FOUND")
    if not access.capabilities & VIEW:
        _audit_denial(
            session,
            user_id=user_id,
            document_id=document_id,
            source_ip=source_ip,
            capability=capability,
        )
        raise DocVaultError("NOT_FOUND")
    if (
        capability == PRINT
        and document.confidentiality is ConfLevel.RESTRICTED
        and access.scope != "admin"
        and not access.explicit_document_capabilities & PRINT
    ):
        _audit_denial(
            session,
            user_id=user_id,
            document_id=document_id,
            source_ip=source_ip,
            capability=capability,
        )
        raise DocVaultError(
            "PRINT_RESTRICTED",
            detail="Restricted documents require an explicit document-level print grant.",
        )
    if not access.capabilities & capability:
        _audit_denial(
            session,
            user_id=user_id,
            document_id=document_id,
            source_ip=source_ip,
            capability=capability,
        )
        raise DocVaultError(
            "FORBIDDEN",
            detail=f"The {capability_name(capability)} capability is required.",
        )

    reason: str | None = None
    if capability == READ and access.scope == "admin":
        reason = (break_glass_reason or "").strip()
        if len(reason) < 10:
            _audit_denial(
                session,
                user_id=user_id,
                document_id=document_id,
                source_ip=source_ip,
                capability=capability,
            )
            raise DocVaultError(
                "VALIDATION_FAILED",
                detail="Administrator content access requires a reason of at least 10 characters.",
            )

    append_event(
        session,
        action="access.allow",
        object_type="document",
        object_id=document_id,
        actor_id=user_id,
        source_ip=source_ip,
        detail={"capability": capability, "scope": access.scope},
    )
    if capability == READ and access.scope == "admin":
        append_event(
            session,
            action="document.breakglass_read",
            object_type="document",
            object_id=document_id,
            actor_id=user_id,
            source_ip=source_ip,
            detail={"reason": reason or ""},
        )
    return document


def _audit_entity_denial(
    session: Session,
    *,
    user_id: uuid.UUID,
    entity_id: uuid.UUID,
    source_ip: str | None,
    capability: int,
) -> None:
    bind = session.get_bind()
    with Session(bind=bind) as audit_session, audit_session.begin():
        append_event(
            audit_session,
            action="access.deny",
            object_type="entity",
            object_id=entity_id,
            actor_id=user_id,
            outcome="deny",
            source_ip=source_ip,
            detail={"capability": capability},
        )


def require_entity(
    session: Session,
    user_id: uuid.UUID,
    entity_id: uuid.UUID,
    capability: int,
    *,
    source_ip: str | None = None,
    include_deleted: bool = False,
) -> Entity:
    """Require one entity capability, hiding entities without ``view``."""
    entity = session.get(Entity, entity_id)
    if entity is None:
        _audit_entity_denial(
            session,
            user_id=user_id,
            entity_id=entity_id,
            source_ip=source_ip,
            capability=capability,
        )
        raise DocVaultError("NOT_FOUND")

    access = resolve_entity_access(session, user_id, entity)
    if entity.deleted_at is not None and not include_deleted:
        _audit_entity_denial(
            session,
            user_id=user_id,
            entity_id=entity_id,
            source_ip=source_ip,
            capability=capability,
        )
        raise DocVaultError("NOT_FOUND")
    if not access.capabilities & VIEW:
        _audit_entity_denial(
            session,
            user_id=user_id,
            entity_id=entity_id,
            source_ip=source_ip,
            capability=capability,
        )
        raise DocVaultError("NOT_FOUND")
    if not access.capabilities & capability:
        _audit_entity_denial(
            session,
            user_id=user_id,
            entity_id=entity_id,
            source_ip=source_ip,
            capability=capability,
        )
        raise DocVaultError(
            "FORBIDDEN",
            detail=f"The {capability_name(capability)} capability is required.",
        )

    append_event(
        session,
        action="access.allow",
        object_type="entity",
        object_id=entity_id,
        actor_id=user_id,
        source_ip=source_ip,
        detail={"capability": capability, "scope": access.scope},
    )
    return entity


def capability_name(capability: int) -> str:
    """Return a stable public label for a capability bit."""
    names = {
        VIEW: "view",
        READ: "read",
        WRITE: "write",
        DELETE: "delete",
        MANAGE_ACL: "manage_acl",
        PRINT: "print",
    }
    return names.get(capability, "requested")


def _subject_predicate(user_id: uuid.UUID, groups: tuple[uuid.UUID, ...]) -> ColumnElement[bool]:
    direct = and_(
        AclEntry.subject_type == AclSubject.USER,
        AclEntry.subject_id == user_id,
    )
    if not groups:
        return direct
    return or_(
        direct,
        and_(
            AclEntry.subject_type == AclSubject.GROUP,
            AclEntry.subject_id.in_(groups),
        ),
    )


def visible_documents(
    session: Session,
    user_id: uuid.UUID,
    *,
    capability: int = VIEW,
    include_deleted: bool = False,
) -> Select[Document]:
    """Build the ACL-filtered document query used by every collection surface."""
    role_caps = _role_capabilities(session, user_id)
    statement = select(Document)
    if not include_deleted or role_caps != ALL:
        statement = statement.where(Document.deleted_at.is_(None))
    if role_caps == ALL:
        return statement

    groups = tuple(_subjects(session, user_id)[1:])
    matching_subject = _subject_predicate(user_id, groups)
    allowed_bits = func.coalesce(
        func.bit_or(
            case(
                (AclEntry.effect == AclEffect.ALLOW, AclEntry.capabilities),
                else_=0,
            )
        ),
        0,
    )
    denied_bits = func.coalesce(
        func.bit_or(
            case(
                (AclEntry.effect == AclEffect.DENY, AclEntry.capabilities),
                else_=0,
            )
        ),
        0,
    )
    docs = (
        select(
            AclEntry.object_id.label("document_id"),
            allowed_bits.label("allowed"),
            denied_bits.label("denied"),
        )
        .where(
            AclEntry.object_type == AclObject.DOCUMENT,
            matching_subject,
        )
        .group_by(AclEntry.object_id)
        .cte("document_access")
    )
    entity_presence = (
        select(AclEntry.object_id.label("entity_id"))
        .join(Entity, Entity.id == AclEntry.object_id)
        .where(
            AclEntry.object_type == AclObject.ENTITY,
            Entity.acl_mode == AclMode.EXPLICIT,
        )
        .group_by(AclEntry.object_id)
        .cte("explicit_entities")
    )
    explicit_docs = (
        select(DocumentEntityLink.document_id.label("document_id"))
        .join(entity_presence, entity_presence.c.entity_id == DocumentEntityLink.entity_id)
        .group_by(DocumentEntityLink.document_id)
        .cte("documents_with_explicit_entity_acl")
    )
    entity_access = (
        select(
            DocumentEntityLink.document_id.label("document_id"),
            allowed_bits.label("allowed"),
            denied_bits.label("denied"),
        )
        .join(
            entity_presence,
            entity_presence.c.entity_id == DocumentEntityLink.entity_id,
        )
        .join(
            AclEntry,
            and_(
                AclEntry.object_type == AclObject.ENTITY,
                AclEntry.object_id == DocumentEntityLink.entity_id,
            ),
        )
        .where(AclEntry.object_type == AclObject.ENTITY, matching_subject)
        .group_by(DocumentEntityLink.document_id)
        .cte("entity_access")
    )
    joined = (
        statement.outerjoin(docs, docs.c.document_id == Document.id)
        .outerjoin(explicit_docs, explicit_docs.c.document_id == Document.id)
        .outerjoin(entity_access, entity_access.c.document_id == Document.id)
    )
    has_doc_scope = Document.acl_mode == AclMode.EXPLICIT
    has_entity_scope = explicit_docs.c.document_id.is_not(None)
    raw_allow = case(
        (has_doc_scope, func.coalesce(docs.c.allowed, 0)),
        (has_entity_scope, func.coalesce(entity_access.c.allowed, 0)),
        else_=role_caps,
    )
    raw_deny = case(
        (has_doc_scope, func.coalesce(docs.c.denied, 0)),
        (has_entity_scope, func.coalesce(entity_access.c.denied, 0)),
        else_=0,
    )
    closed_allow = case(
        (raw_allow.bitwise_and(PRINT) != 0, raw_allow.bitwise_or(READ | VIEW)),
        (raw_allow.bitwise_and(READ) != 0, raw_allow.bitwise_or(VIEW)),
        else_=raw_allow,
    )
    closed_deny = case(
        (raw_deny.bitwise_and(VIEW) != 0, raw_deny.bitwise_or(READ | PRINT)),
        (raw_deny.bitwise_and(READ) != 0, raw_deny.bitwise_or(PRINT)),
        else_=raw_deny,
    )
    effective = case(
        (
            Document.owner_id == user_id,
            closed_allow.bitwise_and(closed_deny.bitwise_not()).bitwise_or(OWNER_FLOOR),
        ),
        else_=closed_allow.bitwise_and(closed_deny.bitwise_not()),
    )
    return joined.where(effective.bitwise_and(capability) != 0)


def visible_entities(
    session: Session,
    user_id: uuid.UUID,
    *,
    include_deleted: bool = False,
) -> Select[Entity]:
    """Build the ACL-filtered entity query used by entity collections."""
    role_caps = _role_capabilities(session, user_id)
    statement = select(Entity)
    if not include_deleted or role_caps != ALL:
        statement = statement.where(Entity.deleted_at.is_(None))
    if role_caps == ALL:
        return statement

    groups = tuple(_subjects(session, user_id)[1:])
    matching_subject = _subject_predicate(user_id, groups)
    allowed = func.coalesce(
        func.bit_or(case((AclEntry.effect == AclEffect.ALLOW, AclEntry.capabilities), else_=0)),
        0,
    )
    denied = func.coalesce(
        func.bit_or(case((AclEntry.effect == AclEffect.DENY, AclEntry.capabilities), else_=0)),
        0,
    )
    explicit_visible = (
        select(AclEntry.object_id)
        .join(Entity, Entity.id == AclEntry.object_id)
        .where(
            AclEntry.object_type == AclObject.ENTITY,
            Entity.acl_mode == AclMode.EXPLICIT,
            matching_subject,
        )
        .group_by(AclEntry.object_id)
        .having(
            allowed.bitwise_and(VIEW | READ | PRINT) != 0,
            denied.bitwise_and(VIEW | READ) == 0,
        )
    )
    explicit = and_(
        Entity.acl_mode == AclMode.EXPLICIT,
        Entity.id.in_(explicit_visible),
    )
    if role_caps & VIEW:
        return statement.where(or_(explicit, Entity.acl_mode == AclMode.INHERIT))
    return statement.where(explicit)


def is_admin(session: Session, user_id: uuid.UUID) -> bool:
    """Check the admin role without caching membership."""
    return _role_capabilities(session, user_id) == ALL


def capability_names(session: Session, user_id: uuid.UUID) -> tuple[str, ...]:
    """Return the vault-wide role capabilities for a session response."""
    mask = _role_capabilities(session, user_id)
    return tuple(name for name, bit in CAPABILITY_BITS.items() if mask & bit)


def capability_mask(names: tuple[str, ...]) -> int:
    """Normalize API capability names to the stored closed bitmask."""
    if not names or any(name not in CAPABILITY_BITS for name in names):
        raise DocVaultError("VALIDATION_FAILED", detail="Unknown or empty capabilities.")
    mask = 0
    for name in names:
        mask |= CAPABILITY_BITS[name]
    return close_up(mask)


def _validate_subject(session: Session, grant: Grant, actor_id: uuid.UUID) -> bool:
    if grant.subject_type is AclSubject.USER:
        exists = session.get(User, grant.subject_id) is not None
        is_self = grant.subject_id == actor_id
    else:
        exists = session.get(Group, grant.subject_id) is not None
        is_self = (
            session.execute(
                select(GroupMember.user_id).where(
                    GroupMember.group_id == grant.subject_id,
                    GroupMember.user_id == actor_id,
                )
            ).scalar_one_or_none()
            is not None
        )
    if not exists:
        raise DocVaultError("VALIDATION_FAILED", detail="An ACL subject does not exist.")
    return is_self


def list_acl(
    session: Session,
    *,
    object_type: AclObject,
    object_id: uuid.UUID,
) -> tuple[Grant, ...]:
    """Return stored grants in stable order."""
    rows = session.execute(
        select(AclEntry)
        .where(AclEntry.object_type == object_type, AclEntry.object_id == object_id)
        .order_by(AclEntry.subject_type, AclEntry.subject_id)
    ).scalars()
    return tuple(
        Grant(
            subject_type=row.subject_type,
            subject_id=row.subject_id,
            capabilities=row.capabilities,
            effect=row.effect,
        )
        for row in rows
    )


def _validate_replacement_grants(
    session: Session,
    grants: tuple[Grant, ...],
    *,
    actor_id: uuid.UUID,
    object_type: AclObject,
    administrator: bool,
    actor_capabilities: int,
    owner_id: uuid.UUID | None,
    existing: dict[tuple[AclSubject, uuid.UUID], Grant],
) -> None:
    keys: set[tuple[AclSubject, uuid.UUID]] = set()
    for grant in grants:
        if grant.capabilities <= 0 or grant.capabilities & ~ALL:
            raise DocVaultError("VALIDATION_FAILED", detail="Invalid ACL capability mask.")
        key = (grant.subject_type, grant.subject_id)
        if key in keys:
            raise DocVaultError(
                "VALIDATION_FAILED",
                detail="Duplicate ACL subjects are not allowed.",
            )
        keys.add(key)
        is_self = _validate_subject(session, grant, actor_id)
        # Re-submitting an entry exactly as it is stored is not a new grant.
        # Without this, a delegate could never save an ACL because their own
        # manage_acl entry would trip the escalation checks below.
        unchanged = existing.get(key) == grant
        if is_self and not administrator and not unchanged:
            raise DocVaultError(
                "VALIDATION_FAILED",
                detail="You cannot grant permissions to yourself; ask an administrator.",
            )
        if grant.effect is AclEffect.DENY and not administrator and not unchanged:
            raise DocVaultError("FORBIDDEN", detail="Only administrators can add deny entries.")
        if not administrator and grant.capabilities & ~actor_capabilities and not unchanged:
            raise DocVaultError(
                "FORBIDDEN",
                detail="You cannot grant capabilities you do not hold.",
            )
        if (
            object_type is AclObject.DOCUMENT
            and not administrator
            and grant.capabilities & MANAGE_ACL
            and owner_id != actor_id
            and not unchanged
        ):
            raise DocVaultError(
                "FORBIDDEN",
                detail="Only the document owner or an administrator can grant manage_acl.",
            )

    if object_type is AclObject.DOCUMENT:
        owner_grant = next(
            (
                grant
                for grant in grants
                if grant.subject_type is AclSubject.USER
                and grant.subject_id == owner_id
                and grant.effect is AclEffect.ALLOW
            ),
            None,
        )
        owner_denial = any(
            grant.subject_type is AclSubject.USER
            and grant.subject_id == owner_id
            and grant.effect is AclEffect.DENY
            and grant.capabilities & OWNER_FLOOR
            for grant in grants
        )
        if (
            owner_grant is None
            or owner_grant.capabilities & OWNER_FLOOR != OWNER_FLOOR
            or owner_denial
        ):
            raise DocVaultError(
                "VALIDATION_FAILED",
                detail="The document owner must retain view, read, write, and manage_acl.",
            )


def replace_acl(
    session: Session,
    *,
    object_type: AclObject,
    object_id: uuid.UUID,
    actor_id: uuid.UUID,
    source_ip: str | None,
    grants: tuple[Grant, ...],
) -> tuple[Grant, ...]:
    """Validate and atomically replace an entity or document ACL."""
    for grant in grants:
        if grant.capabilities <= 0 or grant.capabilities & ~ALL:
            raise DocVaultError("VALIDATION_FAILED", detail="Invalid ACL capability mask.")
    grants = tuple(
        Grant(
            grant.subject_type,
            grant.subject_id,
            close_up(grant.capabilities),
            grant.effect,
        )
        for grant in grants
    )
    administrator = is_admin(session, actor_id)
    actor_access: Access | None = None
    owner_id: uuid.UUID | None = None
    if object_type is AclObject.ENTITY:
        target_entity = session.get(Entity, object_id)
        if target_entity is None:
            raise DocVaultError("NOT_FOUND")
        if not administrator:
            raise DocVaultError("FORBIDDEN", detail="Entity ACLs are administrator-managed.")
        target_entity.acl_mode = AclMode.EXPLICIT
    else:
        document = session.get(Document, object_id)
        if document is None:
            raise DocVaultError("NOT_FOUND")
        owner_id = document.owner_id
        actor_access = resolve_access(session, actor_id, document)
        if not administrator and not actor_access.capabilities & MANAGE_ACL:
            raise DocVaultError("FORBIDDEN", detail="The manage_acl capability is required.")
        document.acl_mode = AclMode.EXPLICIT
    actor_capabilities = (
        ALL if administrator else (actor_access.capabilities if actor_access is not None else 0)
    )
    before = list_acl(session, object_type=object_type, object_id=object_id)
    existing = {(entry.subject_type, entry.subject_id): entry for entry in before}
    _validate_replacement_grants(
        session,
        grants,
        actor_id=actor_id,
        object_type=object_type,
        administrator=administrator,
        actor_capabilities=actor_capabilities,
        owner_id=owner_id,
        existing=existing,
    )
    session.execute(
        delete(AclEntry).where(
            AclEntry.object_type == object_type,
            AclEntry.object_id == object_id,
        )
    )
    for grant in grants:
        session.add(
            AclEntry(
                object_type=object_type,
                object_id=object_id,
                subject_type=grant.subject_type,
                subject_id=grant.subject_id,
                capabilities=grant.capabilities,
                effect=grant.effect,
                created_by=actor_id,
                updated_by=actor_id,
            )
        )
    session.flush()
    append_event(
        session,
        action=f"{object_type.value}.acl_changed",
        object_type=object_type.value,
        object_id=object_id,
        actor_id=actor_id,
        source_ip=source_ip,
        detail={
            "before": [
                {
                    "subject_type": entry.subject_type.value,
                    "subject_id": str(entry.subject_id),
                    "capabilities": entry.capabilities,
                    "effect": entry.effect.value,
                }
                for entry in before
            ],
            "after": [
                {
                    "subject_type": entry.subject_type.value,
                    "subject_id": str(entry.subject_id),
                    "capabilities": entry.capabilities,
                    "effect": entry.effect.value,
                }
                for entry in grants
            ],
        },
    )
    return list_acl(session, object_type=object_type, object_id=object_id)


def effective_access_for_document(
    session: Session, document: Document
) -> tuple[tuple[uuid.UUID, int], ...]:
    """Resolve access for the bounded user population shown in the admin panel."""
    user_ids = session.execute(select(User.id).order_by(User.id).limit(2000)).scalars()
    return tuple(
        (user_id, resolve_access(session, user_id, document).capabilities) for user_id in user_ids
    )


def effective_access_for_entity(
    session: Session, entity: Entity
) -> tuple[tuple[uuid.UUID, int], ...]:
    """Resolve entity permissions for the bounded user population."""
    user_ids = session.execute(select(User.id).order_by(User.id).limit(2000)).scalars()
    return tuple(
        (user_id, resolve_entity_access(session, user_id, entity).capabilities)
        for user_id in user_ids
    )
