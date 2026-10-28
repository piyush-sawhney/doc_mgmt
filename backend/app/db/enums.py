"""PostgreSQL enum types shared by the models and the migration.

Values are the lowercase strings stored in the database. Python names are
uppercase only so a reader can tell an enum member from a string literal.
"""

from __future__ import annotations

from enum import StrEnum


class UserStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    LOCKED = "locked"


class RoleName(StrEnum):
    ADMIN = "admin"
    EDITOR = "editor"
    READER = "reader"
    AUDITOR = "auditor"


class SessionState(StrEnum):
    PENDING_TOTP = "pending_totp"
    ACTIVE = "active"


class EntityType(StrEnum):
    INDIVIDUAL = "individual"
    COMPANY = "company"
    LLP = "llp"
    PARTNERSHIP = "partnership"
    TRUST = "trust"
    HUF = "huf"
    SOCIETY = "society"
    GOVERNMENT = "government"
    OTHER = "other"


class AclMode(StrEnum):
    INHERIT = "inherit"
    EXPLICIT = "explicit"


class EntityStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    MERGED = "merged"


class Gender(StrEnum):
    FEMALE = "female"
    MALE = "male"
    OTHER = "other"
    UNDISCLOSED = "undisclosed"


class PersonRole(StrEnum):
    SELF = "self"
    DIRECTOR = "director"
    SIGNATORY = "signatory"
    GUARANTOR = "guarantor"
    PARTNER = "partner"
    TRUSTEE = "trustee"
    BENEFICIARY = "beneficiary"
    OTHER = "other"


class ConfLevel(StrEnum):
    NORMAL = "normal"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


class DocStatus(StrEnum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    DELETED = "deleted"


class LinkRole(StrEnum):
    BELONGS_TO = "belongs_to"
    PROVES = "proves"
    GUARANTOR_FOR = "guarantor_for"
    ADDRESS_PROOF_OF = "address_proof_of"
    OTHER = "other"


class SideKind(StrEnum):
    FRONT = "front"
    BACK = "back"


class AclObject(StrEnum):
    DOCUMENT = "document"
    ENTITY = "entity"


class AclSubject(StrEnum):
    USER = "user"
    GROUP = "group"


class AclEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class AuditOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    ERROR = "error"


class RenditionKind(StrEnum):
    PREVIEW = "preview"
    PAGE = "page"


class PrintStatus(StrEnum):
    COMPLETED = "completed"
    DENIED = "denied"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


# The six capability bits (docs/04 §6, docs/06 §2).
VIEW = 1
READ = 2
WRITE = 4
DELETE = 8
MANAGE_ACL = 16
PRINT = 32
ALL_CAPABILITIES = VIEW | READ | WRITE | DELETE | MANAGE_ACL | PRINT
