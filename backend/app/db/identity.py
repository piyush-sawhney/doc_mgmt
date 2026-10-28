"""The ``settings`` rows that tie a database to a vault.

``vault_id`` and ``schema_version`` are written once, after the schema exists,
and compared on every open. The manifest is the authority: if the database
disagrees, the app refuses to start rather than write into a stranger's schema
(docs/05 §9, docs/08 §2.2).
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Connection, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.core.errors import DocVaultError
from app.crypto.keys import decrypt_column, encrypt_column
from app.db.models import Setting

TABLE = "settings"
COLUMN = "value"
VAULT_ID_KEY = "vault_id"
SCHEMA_VERSION_KEY = "schema_version"
IDENTITY_KEYS = (VAULT_ID_KEY, SCHEMA_VERSION_KEY)


@dataclass(frozen=True, slots=True)
class DatabaseIdentity:
    """The two values that prove a database belongs to this vault."""

    vault_id: str
    schema_version: int


def _seal(meta_key: bytes, value: str) -> bytes:
    sealed = encrypt_column(meta_key, TABLE, COLUMN, value)
    if sealed is None:  # pragma: no cover - value is never None
        raise DocVaultError("CONFIG_INVALID", detail=f"Could not encrypt {TABLE}.{COLUMN}.")
    return sealed


def _open(meta_key: bytes, row: bytes | None) -> str | None:
    return decrypt_column(meta_key, TABLE, COLUMN, row)


def write_identity(
    connection: Connection,
    *,
    meta_key: bytes,
    vault_id: str,
    schema_version: int,
) -> None:
    """Insert or update the identity rows. The caller owns the transaction."""
    values = {VAULT_ID_KEY: vault_id, SCHEMA_VERSION_KEY: str(schema_version)}
    for key, value in values.items():
        statement = (
            pg_insert(Setting)
            .values(key=key, value=None, value_enc=_seal(meta_key, value))
            .on_conflict_do_update(
                index_elements=[Setting.key],
                set_={"value_enc": _seal(meta_key, value), "value": None},
            )
        )
        connection.execute(statement)


def read_identity(connection: Connection, *, meta_key: bytes) -> DatabaseIdentity | None:
    """Return the identity, or ``None`` on a schema that has never been initialised."""
    rows = dict(
        connection.execute(
            select(Setting.key, Setting.value_enc).where(Setting.key.in_(IDENTITY_KEYS))
        ).all()
    )
    if set(rows) != set(IDENTITY_KEYS):
        return None
    vault_id = _open(meta_key, rows[VAULT_ID_KEY])
    schema_version = _open(meta_key, rows[SCHEMA_VERSION_KEY])
    if vault_id is None or schema_version is None:
        return None
    try:
        parsed = int(schema_version)
    except ValueError as exc:
        raise DocVaultError(
            "VAULT_DB_MISMATCH", detail="settings.schema_version is not an integer."
        ) from exc
    return DatabaseIdentity(vault_id=vault_id, schema_version=parsed)


def require_matching_identity(
    connection: Connection,
    *,
    meta_key: bytes,
    expected_vault_id: str,
    supported_schema: int,
) -> DatabaseIdentity:
    """Refuse a database that belongs to another vault or a newer schema."""
    identity = read_identity(connection, meta_key=meta_key)
    if identity is None:
        raise DocVaultError(
            "VAULT_DB_MISMATCH",
            detail="The database has no vault identity; run docvault migrate.",
            remediation="Run docvault migrate against this vault and database.",
        )
    if identity.vault_id != expected_vault_id:
        raise DocVaultError(
            "VAULT_DB_MISMATCH",
            detail="settings.vault_id does not match manifest.json.",
        )
    if identity.schema_version > supported_schema:
        raise DocVaultError(
            "SCHEMA_TOO_NEW",
            detail=(
                f"Database schema {identity.schema_version} is newer than "
                f"this application ({supported_schema})."
            ),
        )
    return identity
