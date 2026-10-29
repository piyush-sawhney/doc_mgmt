"""Administrative account and group operations."""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app.core.errors import DocVaultError
from app.core.time import now_utc
from app.crypto.keys import VaultKeys, decrypt_column, encrypt_column
from app.db.enums import AclSubject, RoleName, UserStatus
from app.db.models.identity import Group, GroupMember, User, UserRole
from app.db.models.identity import Session as DbSession
from app.db.models.operations import AclEntry
from app.services.audit import append_event
from app.services.auth import hash_password, validate_password


@dataclass(frozen=True, slots=True)
class UserRecord:
    """Decrypted user fields safe for an admin response."""

    id: uuid.UUID
    username: str
    display_name: str
    status: UserStatus
    roles: tuple[RoleName, ...]
    must_change_password: bool
    row_version: int


@dataclass(frozen=True, slots=True)
class GroupRecord:
    """Decrypted group fields safe for an admin response."""

    id: uuid.UUID
    name: str
    description: str | None
    is_system: bool
    row_version: int
    user_ids: tuple[uuid.UUID, ...] = ()


def _user_record(session: Session, keys: VaultKeys, user: User) -> UserRecord:
    username = decrypt_column(keys.meta_key, "users", "username_enc", user.username_enc)
    display_name = decrypt_column(keys.meta_key, "users", "display_name_enc", user.display_name_enc)
    if username is None or display_name is None:
        raise DocVaultError("COLUMN_TAMPERED", detail="Required user identity is null.")
    roles = tuple(
        sorted(
            (
                row.role
                for row in session.execute(
                    select(UserRole).where(UserRole.user_id == user.id)
                ).scalars()
            ),
            key=lambda role: role.value,
        )
    )
    return UserRecord(
        id=user.id,
        username=username,
        display_name=display_name,
        status=user.status,
        roles=roles,
        must_change_password=user.must_change_password,
        row_version=user.row_version,
    )


def list_users(
    session: Session,
    keys: VaultKeys,
    *,
    status: UserStatus | None = None,
    role: RoleName | None = None,
    query: str | None = None,
) -> list[UserRecord]:
    """List users using encrypted-field decryption only at the admin boundary."""
    statement = select(User).order_by(User.created_at, User.id)
    if status is not None:
        statement = statement.where(User.status == status)
    if role is not None:
        statement = statement.join(UserRole).where(UserRole.role == role)
    users = session.execute(statement.limit(2000)).scalars().unique()
    records = [_user_record(session, keys, user) for user in users]
    if query:
        prefix = query.strip().casefold()
        records = [
            record
            for record in records
            if record.username.casefold().startswith(prefix)
            or record.display_name.casefold().startswith(prefix)
        ]
    return records


def get_user(session: Session, keys: VaultKeys, user_id: uuid.UUID) -> UserRecord:
    """Load one user for an administrator."""
    user = session.get(User, user_id)
    if user is None:
        raise DocVaultError("NOT_FOUND")
    return _user_record(session, keys, user)


def _expected_version(row_version: int, expected: int | None) -> None:
    if expected is None:
        raise DocVaultError("PRECONDITION_REQUIRED")
    if expected != row_version:
        raise DocVaultError("CONFLICT", detail="The resource changed; reload before editing.")


def _has_role(session: Session, user_id: uuid.UUID, role: RoleName) -> bool:
    return (
        session.execute(
            select(UserRole.user_id).where(
                UserRole.user_id == user_id,
                UserRole.role == role,
            )
        ).scalar_one_or_none()
        is not None
    )


def _ensure_active_admin_remains(
    session: Session,
    user: User,
    *,
    candidate_status: UserStatus,
    candidate_roles: tuple[RoleName, ...],
) -> None:
    if user.status is not UserStatus.ACTIVE or not _has_role(session, user.id, RoleName.ADMIN):
        return
    if candidate_status is UserStatus.ACTIVE and RoleName.ADMIN in candidate_roles:
        return
    other_admins = session.execute(
        select(func.count())
        .select_from(User)
        .join(UserRole, UserRole.user_id == User.id)
        .where(
            User.id != user.id,
            User.status == UserStatus.ACTIVE,
            UserRole.role == RoleName.ADMIN,
        )
    ).scalar_one()
    if other_admins == 0:
        raise DocVaultError(
            "VALIDATION_FAILED",
            detail="The last active admin cannot be disabled or lose the admin role.",
        )


def update_user(
    session: Session,
    keys: VaultKeys,
    user_id: uuid.UUID,
    *,
    expected_version: int | None,
    actor_id: uuid.UUID,
    source_ip: str | None,
    display_name: str | None = None,
    status: UserStatus | None = None,
    roles: tuple[RoleName, ...] | None = None,
) -> UserRecord:
    """Update an account with optimistic concurrency and last-admin protection."""
    user = session.execute(
        select(User).where(User.id == user_id).with_for_update()
    ).scalar_one_or_none()
    if user is None:
        raise DocVaultError("NOT_FOUND")
    _expected_version(user.row_version, expected_version)
    current_roles = tuple(
        session.execute(select(UserRole.role).where(UserRole.user_id == user.id)).scalars()
    )
    next_roles = roles if roles is not None else current_roles
    next_status = status if status is not None else user.status
    if not next_roles:
        raise DocVaultError(
            "VALIDATION_FAILED",
            detail="A user must have at least one role.",
        )
    _ensure_active_admin_remains(
        session,
        user,
        candidate_status=next_status,
        candidate_roles=next_roles,
    )
    before: dict[str, Any] = {
        "status": user.status.value,
        "roles": sorted(role.value for role in current_roles),
    }
    if display_name is not None:
        display_name = display_name.strip()
        if not display_name:
            raise DocVaultError("VALIDATION_FAILED", detail="Display name cannot be empty.")
        display_name_enc = encrypt_column(
            keys.meta_key,
            "users",
            "display_name_enc",
            display_name,
        )
        if display_name_enc is None:  # pragma: no cover - non-null input always encrypts
            raise DocVaultError("INTERNAL_ERROR")
        user.display_name_enc = display_name_enc
    user.status = next_status
    if roles is not None:
        session.execute(delete(UserRole).where(UserRole.user_id == user.id))
        for item in sorted(set(next_roles), key=lambda value: value.value):
            session.add(UserRole(user_id=user.id, role=item))
    if next_status is not UserStatus.ACTIVE:
        session.execute(
            update(DbSession)
            .where(DbSession.user_id == user.id, DbSession.revoked_at.is_(None))
            .values(revoked_at=now_utc())
        )
    user.row_version += 1
    append_event(
        session,
        action="user.update",
        object_type="user",
        object_id=user.id,
        actor_id=actor_id,
        source_ip=source_ip,
        detail={
            "before": before,
            "after": {
                "status": next_status.value,
                "roles": sorted(role.value for role in next_roles),
            },
            "display_name_changed": display_name is not None,
        },
    )
    session.flush()
    return _user_record(session, keys, user)


def reset_password(
    session: Session,
    user_id: uuid.UUID,
    *,
    actor_id: uuid.UUID,
    source_ip: str | None,
) -> str:
    """Set a generated one-time password and revoke every existing session."""
    user = session.execute(
        select(User).where(User.id == user_id).with_for_update()
    ).scalar_one_or_none()
    if user is None:
        raise DocVaultError("NOT_FOUND")
    temporary_password = secrets.token_urlsafe(18)
    validate_password(temporary_password)
    user.password_hash = hash_password(temporary_password)
    user.must_change_password = True
    user.password_changed_at = now_utc()
    user.row_version += 1
    session.execute(
        update(DbSession)
        .where(DbSession.user_id == user.id, DbSession.revoked_at.is_(None))
        .values(revoked_at=now_utc())
    )
    append_event(
        session,
        action="user.password.reset",
        object_type="user",
        object_id=user.id,
        actor_id=actor_id,
        source_ip=source_ip,
    )
    return temporary_password


def revoke_user_sessions(
    session: Session,
    user_id: uuid.UUID,
    *,
    actor_id: uuid.UUID,
    source_ip: str | None,
) -> int:
    """Revoke all active sessions for one account."""
    if session.get(User, user_id) is None:
        raise DocVaultError("NOT_FOUND")
    count = session.execute(
        select(func.count())
        .select_from(DbSession)
        .where(DbSession.user_id == user_id, DbSession.revoked_at.is_(None))
    ).scalar_one()
    session.execute(
        update(DbSession)
        .where(DbSession.user_id == user_id, DbSession.revoked_at.is_(None))
        .values(revoked_at=now_utc())
    )
    append_event(
        session,
        action="user.sessions.revoke",
        object_type="user",
        object_id=user_id,
        actor_id=actor_id,
        source_ip=source_ip,
        detail={"revoked": count},
    )
    return count


def create_group(
    session: Session,
    keys: VaultKeys,
    *,
    name: str,
    description: str | None,
    actor_id: uuid.UUID,
    source_ip: str | None,
) -> GroupRecord:
    """Create a named sharing group."""
    clean_name = name.strip()
    if not clean_name:
        raise DocVaultError("VALIDATION_FAILED", detail="Group name cannot be empty.")
    duplicate = session.execute(
        select(Group.id).where(Group.name == clean_name)
    ).scalar_one_or_none()
    if duplicate is not None:
        raise DocVaultError("CONFLICT", detail="That group name already exists.")
    group = Group(
        name=clean_name,
        description_enc=encrypt_column(
            keys.meta_key,
            "groups",
            "description_enc",
            description.strip() if description else None,
        ),
    )
    session.add(group)
    session.flush()
    append_event(
        session,
        action="group.create",
        object_type="group",
        object_id=group.id,
        actor_id=actor_id,
        source_ip=source_ip,
    )
    return GroupRecord(
        id=group.id,
        name=group.name,
        description=description.strip() if description else None,
        is_system=False,
        row_version=group.row_version,
    )


def _group_record(session: Session, keys: VaultKeys, group: Group) -> GroupRecord:
    description = decrypt_column(
        keys.meta_key,
        "groups",
        "description_enc",
        group.description_enc,
    )
    users = tuple(
        session.execute(
            select(GroupMember.user_id)
            .where(GroupMember.group_id == group.id)
            .order_by(GroupMember.user_id)
        ).scalars()
    )
    return GroupRecord(
        id=group.id,
        name=group.name,
        description=description,
        is_system=group.is_system,
        row_version=group.row_version,
        user_ids=users,
    )


def list_groups(session: Session, keys: VaultKeys) -> list[GroupRecord]:
    """List all groups and their current membership."""
    groups = session.execute(select(Group).order_by(Group.name)).scalars()
    return [_group_record(session, keys, group) for group in groups]


def get_group(session: Session, keys: VaultKeys, group_id: uuid.UUID) -> GroupRecord:
    """Load one group and its current membership."""
    group = session.get(Group, group_id)
    if group is None:
        raise DocVaultError("NOT_FOUND")
    return _group_record(session, keys, group)


def update_group(
    session: Session,
    keys: VaultKeys,
    group_id: uuid.UUID,
    *,
    expected_version: int | None,
    name: str | None,
    description: str | None,
    actor_id: uuid.UUID,
    source_ip: str | None,
) -> GroupRecord:
    """Update group metadata with an ETag check."""
    group = session.execute(
        select(Group).where(Group.id == group_id).with_for_update()
    ).scalar_one_or_none()
    if group is None:
        raise DocVaultError("NOT_FOUND")
    _expected_version(group.row_version, expected_version)
    if name is not None:
        clean_name = name.strip()
        if not clean_name:
            raise DocVaultError("VALIDATION_FAILED", detail="Group name cannot be empty.")
        duplicate = session.execute(
            select(Group.id).where(Group.name == clean_name, Group.id != group.id)
        ).scalar_one_or_none()
        if duplicate is not None:
            raise DocVaultError("CONFLICT", detail="That group name already exists.")
        group.name = clean_name
    if description is not None:
        group.description_enc = encrypt_column(
            keys.meta_key,
            "groups",
            "description_enc",
            description.strip(),
        )
    group.row_version += 1
    append_event(
        session,
        action="group.update",
        object_type="group",
        object_id=group.id,
        actor_id=actor_id,
        source_ip=source_ip,
        detail={"name_changed": name is not None, "description_changed": description is not None},
    )
    session.flush()
    return _group_record(session, keys, group)


def replace_group_members(
    session: Session,
    keys: VaultKeys,
    group_id: uuid.UUID,
    user_ids: tuple[uuid.UUID, ...],
    *,
    actor_id: uuid.UUID,
    source_ip: str | None,
) -> GroupRecord:
    """Atomically replace membership after validating every target account."""
    group = session.execute(
        select(Group).where(Group.id == group_id).with_for_update()
    ).scalar_one_or_none()
    if group is None:
        raise DocVaultError("NOT_FOUND")
    unique_ids = tuple(sorted(set(user_ids)))
    if unique_ids:
        found = set(session.execute(select(User.id).where(User.id.in_(unique_ids))).scalars())
        if found != set(unique_ids):
            raise DocVaultError("NOT_FOUND", detail="One or more users do not exist.")
    before = tuple(
        session.execute(
            select(GroupMember.user_id).where(GroupMember.group_id == group.id)
        ).scalars()
    )
    session.execute(delete(GroupMember).where(GroupMember.group_id == group.id))
    session.add_all(GroupMember(group_id=group.id, user_id=user_id) for user_id in unique_ids)
    group.row_version += 1
    append_event(
        session,
        action="group.members.replace",
        object_type="group",
        object_id=group.id,
        actor_id=actor_id,
        source_ip=source_ip,
        detail={
            "before_count": len(before),
            "after_count": len(unique_ids),
        },
    )
    session.flush()
    return _group_record(session, keys, group)


def delete_group(
    session: Session,
    group_id: uuid.UUID,
    *,
    expected_version: int | None,
    actor_id: uuid.UUID,
    source_ip: str | None,
) -> None:
    """Delete a non-system group and remove its now-invalid ACL entries."""
    group = session.execute(
        select(Group).where(Group.id == group_id).with_for_update()
    ).scalar_one_or_none()
    if group is None:
        raise DocVaultError("NOT_FOUND")
    _expected_version(group.row_version, expected_version)
    if group.is_system:
        raise DocVaultError(
            "VALIDATION_FAILED",
            detail="System groups cannot be deleted.",
        )
    acl_count = session.execute(
        select(func.count())
        .select_from(AclEntry)
        .where(
            AclEntry.subject_type == AclSubject.GROUP,
            AclEntry.subject_id == group.id,
        )
    ).scalar_one()
    session.execute(
        delete(AclEntry).where(
            AclEntry.subject_type == AclSubject.GROUP,
            AclEntry.subject_id == group.id,
        )
    )
    append_event(
        session,
        action="group.delete",
        object_type="group",
        object_id=group.id,
        actor_id=actor_id,
        source_ip=source_ip,
        detail={"acl_entries_removed": acl_count},
    )
    session.delete(group)
