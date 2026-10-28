"""Alembic environment for DocVault.

The database URL never lives in ``alembic.ini``. It comes from, in order:

1. a live SQLAlchemy connection in ``config.attributes["connection"]`` (tests),
2. ``-x dsn=...`` on the command line,
3. ``DOCVAULT_DSN`` in the environment.

This keeps development DSNs out of the repository and lets the test fixture
run migrations on its own temporary database.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import Connection, engine_from_config, pool

# ``alembic`` is run from ``backend/``; the explicit path also makes an
# invocation from the repository root work.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _database_url() -> str:
    x_arguments = context.get_x_argument(as_dictionary=True)
    url = x_arguments.get("dsn") or os.environ.get("DOCVAULT_DSN")
    if url:
        return url
    configured = config.get_main_option("sqlalchemy.url")
    if configured:
        return configured
    raise RuntimeError("No database URL. Pass -x dsn=postgresql+psycopg://... or set DOCVAULT_DSN.")


def run_migrations_offline() -> None:
    """Emit SQL without connecting, for review."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run against a connection supplied by a caller, or create one."""
    supplied = config.attributes.get("connection")
    if supplied is not None:
        _run(supplied)
        return

    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url()
    engine = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with engine.connect() as connection:
        _run(connection)
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
