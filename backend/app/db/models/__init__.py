"""The complete schema, re-exported so Alembic sees every table.

Importing this module is the only supported way to populate ``Base.metadata``.
A model that is not listed here will silently be absent from migrations.
"""

from __future__ import annotations

from app.db.base import Base
from app.db.models.documents import (
    DocType,
    Document,
    DocumentEntityLink,
    DocumentTag,
    DocumentVersion,
    Tag,
    VersionRenderSettings,
)
from app.db.models.entities import Entity, EntityPerson, Identifier, Person
from app.db.models.identity import Group, GroupMember, Session, User, UserRole
from app.db.models.operations import (
    AclEntry,
    AuditEvent,
    DownloadTicket,
    IdempotencyKey,
    PrintItem,
    PrintJob,
    Rendition,
    Setting,
)

__all__ = [
    "AclEntry",
    "AuditEvent",
    "Base",
    "DocType",
    "Document",
    "DocumentEntityLink",
    "DocumentTag",
    "DocumentVersion",
    "DownloadTicket",
    "Entity",
    "EntityPerson",
    "Group",
    "GroupMember",
    "IdempotencyKey",
    "Identifier",
    "Person",
    "PrintItem",
    "PrintJob",
    "Rendition",
    "Session",
    "Setting",
    "Tag",
    "User",
    "UserRole",
    "VersionRenderSettings",
]
