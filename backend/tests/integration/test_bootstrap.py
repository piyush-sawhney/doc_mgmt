"""Provisioning, migration, and the vault identity stamp.

These tests create a real role and database on the throwaway cluster, then drop
them. The database is never mocked: provisioning is DDL, and DDL is the thing
most likely to be wrong.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from app.core.errors import DocVaultError
from app.db import bootstrap, connect, migrate
from app.db.provision import provision
from app.db.schema import SCHEMA_VERSION

from .conftest import Pair

VAULT_ID = "0192f0c4-7a1e-7c3b-9a55-2c1f0b6d4e11"
STRANGER_ID = "0192f0c4-0000-7000-8000-000000000000"


def test_provision_creates_an_unprivileged_role_and_its_database(
    pg_admin_dsn: str, pair: Pair
) -> None:
    admin = create_engine(pg_admin_dsn, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT rolsuper, rolcreatedb, rolcreaterole, rolcanlogin "
                    "FROM pg_roles WHERE rolname = :role"
                ),
                {"role": pair.role},
            ).one()
            assert tuple(row) == (False, False, False, True)
            owner = connection.execute(
                text("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = :database"),
                {"database": pair.database},
            ).scalar_one()
            assert owner == pair.role
    finally:
        admin.dispose()


def test_provision_adopts_an_existing_pair(pg_admin_dsn: str, pair: Pair) -> None:
    again = provision(
        pg_admin_dsn,
        database=pair.database,
        role=pair.role,
        password=pair.password,
    )
    assert again.role_created is False
    assert again.database_created is False


def test_migrate_is_idempotent_and_reports_the_head(pair: Pair) -> None:
    migrate.upgrade(pair.dsn)
    migrate.upgrade(pair.dsn)
    engine = create_engine(pair.dsn)
    try:
        with engine.connect() as connection:
            assert migrate.current_revision(connection) == "7e4c2b9a1f30"
    finally:
        engine.dispose()


def test_bootstrap_stamps_the_vault_and_refuses_a_stranger(pair: Pair, keys) -> None:
    migrate.upgrade(pair.dsn)
    engine = create_engine(pair.dsn)
    try:
        with engine.connect() as connection:
            result = bootstrap.bootstrap_database(
                connection,
                meta_key=keys.meta_key,
                vault_id=VAULT_ID,
            )
            assert result.schema_version == SCHEMA_VERSION
            assert result.seed.categories_inserted == 8
            assert result.seed.types_inserted == 73
            assert result.stamped is True

            identity = bootstrap.check_bootstrap(
                connection,
                meta_key=keys.meta_key,
                vault_id=VAULT_ID,
            )
            assert identity.schema_version == SCHEMA_VERSION

            with pytest.raises(DocVaultError) as excinfo:
                bootstrap.check_bootstrap(
                    connection,
                    meta_key=keys.meta_key,
                    vault_id=STRANGER_ID,
                )
            assert excinfo.value.code == "VAULT_DB_MISMATCH"

            # A second run changes nothing and does not restamp.
            again = bootstrap.bootstrap_database(
                connection,
                meta_key=keys.meta_key,
                vault_id=VAULT_ID,
            )
            assert again.seed.inserted == 0
            assert again.stamped is False
    finally:
        engine.dispose()


def test_the_app_role_cannot_create_a_database(pair: Pair) -> None:
    engine = create_engine(pair.dsn, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection, pytest.raises(DBAPIError) as excinfo:
            connection.execute(text(f'CREATE DATABASE "forbidden_{uuid.uuid4().hex[:8]}"'))
        assert getattr(excinfo.value.orig, "sqlstate", None) == "42501"
    finally:
        engine.dispose()


def test_the_server_is_reported_as_supported(pg_admin_dsn: str) -> None:
    engine = connect.create_database_engine(pg_admin_dsn)
    try:
        info = connect.require_supported_server(engine)
        assert info.major == 18
    finally:
        engine.dispose()
