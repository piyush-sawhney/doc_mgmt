"""Bringing a database up to the schema this build expects.

The order matters: migrate, then seed, then stamp the identity. A failure at
any step leaves the next `docvault migrate` able to retry, because every step is
idempotent.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Connection, Engine

from app.core.config import LoadedSettings
from app.core.errors import DocVaultError
from app.db import connect, identity, migrate
from app.db.credentials import Credential, credential_path, load_credential
from app.db.schema import SCHEMA_VERSION
from app.db.seed import SeedResult, seed_catalogue


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    seed: SeedResult
    schema_version: int
    stamped: bool


def credential_for(loaded: LoadedSettings) -> Credential:
    if loaded.path is None:  # pragma: no cover - load_settings always sets it
        raise DocVaultError("CONFIG_INVALID", detail="No configuration file.")
    return load_credential(credential_path(loaded.path))


def engine_for(loaded: LoadedSettings, credential: Credential | None = None) -> Engine:
    """An app-role engine with the stored password injected."""
    stored = credential or credential_for(loaded)
    return connect.create_database_engine(loaded.settings.database.dsn, password=stored.password)


def migrate_database(loaded: LoadedSettings, credential: Credential | None = None) -> None:
    """Check the server, then apply every migration."""
    stored = credential or credential_for(loaded)
    engine = connect.create_database_engine(loaded.settings.database.dsn, password=stored.password)
    try:
        connect.require_supported_server(engine)
    finally:
        engine.dispose()
    dsn = connect.database_url(loaded.settings.database.dsn, stored.password)
    migrate.upgrade(dsn)


def bootstrap_database(
    connection: Connection,
    *,
    meta_key: bytes,
    vault_id: str,
) -> BootstrapResult:
    """Seed the catalogue and stamp the vault identity.

    Each step commits on its own: the seed is idempotent, so a crash before the
    identity is stamped is repaired by running `docvault migrate` again.
    """
    existing = identity.read_identity(connection, meta_key=meta_key)
    if existing is not None and existing.vault_id != vault_id:
        raise DocVaultError(
            "VAULT_DB_MISMATCH",
            detail="The database belongs to a different vault.",
        )
    if existing is not None and existing.schema_version > SCHEMA_VERSION:
        raise DocVaultError(
            "SCHEMA_TOO_NEW",
            detail=(
                f"The database schema is {existing.schema_version}; "
                f"this app supports {SCHEMA_VERSION}."
            ),
        )

    seed = seed_catalogue(connection, meta_key=meta_key)
    connection.commit()
    identity.write_identity(
        connection,
        meta_key=meta_key,
        vault_id=vault_id,
        schema_version=SCHEMA_VERSION,
    )
    connection.commit()
    return BootstrapResult(
        seed=seed,
        schema_version=SCHEMA_VERSION,
        stamped=existing is None or existing.schema_version != SCHEMA_VERSION,
    )


def check_bootstrap(
    connection: Connection, *, meta_key: bytes, vault_id: str
) -> identity.DatabaseIdentity:
    """Verify the identity of an already-provisioned database."""
    if migrate.current_revision(connection) is None:
        raise DocVaultError(
            "VAULT_DB_MISMATCH",
            detail="The database has no schema.",
            remediation="Run docvault migrate against this vault and database.",
        )
    return identity.require_matching_identity(
        connection,
        meta_key=meta_key,
        expected_vault_id=vault_id,
        supported_schema=SCHEMA_VERSION,
    )
