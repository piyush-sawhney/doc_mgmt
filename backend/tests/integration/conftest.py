"""PostgreSQL 18 fixtures for the integration suite.

Every test gets a real, empty database on the development cluster. Nothing is
mocked and SQLite is never used: the schema depends on PostgreSQL enums,
partial indexes, and PL/pgSQL triggers (docs/14 §6, docs/17 S1).
"""

from __future__ import annotations

import os
import secrets
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError

from app.db.provision import provision
from app.db.seed import SeedResult, seed_catalogue

BACKEND_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ADMIN_DSN = "postgresql+psycopg://postgres@127.0.0.1:5433/postgres"
ADMIN_DSN_ENV = "DOCVAULT_TEST_PG_DSN"


@dataclass(frozen=True, slots=True)
class Pair:
    """A freshly provisioned app role, its database, and both DSN spellings."""

    role: str
    database: str
    password: str
    dsn: str
    libpq_dsn: str


def _admin_dsn() -> str:
    return os.environ.get(ADMIN_DSN_ENV, DEFAULT_ADMIN_DSN)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Mark everything in this directory so ``-m 'not integration'`` skips it."""
    marker = pytest.mark.integration
    for item in items:
        if "tests/integration/" in item.nodeid.replace("\\", "/"):
            item.add_marker(marker)


@pytest.fixture(scope="session")
def pg_admin_dsn() -> str:
    """Fail fast with a skip when the throwaway cluster is not running."""
    dsn = _admin_dsn()
    engine = create_engine(dsn, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            version = int(
                connection.execute(
                    text("SELECT current_setting('server_version_num')")
                ).scalar_one()
            )
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL is not reachable at {dsn}: {exc.orig}")
    finally:
        engine.dispose()

    if not 180_000 <= version < 190_000:
        pytest.skip(f"PostgreSQL 18 is required; the server reports {version}.")
    return dsn


@pytest.fixture
def pair(pg_admin_dsn: str) -> Iterator[Pair]:
    """Provision a role and database, then drop both, even on failure."""
    suffix = uuid.uuid4().hex[:10]
    role = f"docvault_test_{suffix}"
    database = f"docvault_test_{suffix}"
    password = secrets.token_urlsafe(24)
    provision(pg_admin_dsn, database=database, role=role, password=password)
    url = make_url(pg_admin_dsn).set(username=role, password=password, database=database)
    # The subprocess DSN never carries the password; PGPASSFILE supplies it.
    libpq = make_url(pg_admin_dsn).set(drivername="postgresql", username=role, database=database)
    try:
        yield Pair(
            role=role,
            database=database,
            password=password,
            dsn=url.render_as_string(hide_password=False),
            libpq_dsn=libpq.render_as_string(hide_password=False),
        )
    finally:
        admin = create_engine(pg_admin_dsn, isolation_level="AUTOCOMMIT")
        try:
            with admin.connect() as connection:
                connection.execute(text(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
                connection.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
        finally:
            admin.dispose()


def _alembic_config(url: str) -> Config:
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    return config


@pytest.fixture
def database_url(pg_admin_dsn: str) -> Iterator[str]:
    """Create a fresh database, migrate it, and drop it afterwards."""
    name = f"docvault_test_{uuid.uuid4().hex[:12]}"
    admin = create_engine(pg_admin_dsn, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))

    base = pg_admin_dsn.rsplit("/", 1)[0]
    url = f"{base}/{name}"
    try:
        command.upgrade(_alembic_config(url), "head")
        yield url
    finally:
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.fixture
def connection(database_url: str) -> Iterator[Connection]:
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            yield connection
    finally:
        engine.dispose()


@pytest.fixture
def seeded(connection: Connection, keys) -> SeedResult:
    result = seed_catalogue(connection, meta_key=keys.meta_key)
    connection.commit()
    return result
