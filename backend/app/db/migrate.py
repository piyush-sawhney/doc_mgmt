"""Running Alembic against a live database.

The revision files live beside the package (``backend/migrations``), not inside
it. ``DOCVAULT_MIGRATIONS`` overrides the location for a packaged build; the
fallback is the repository layout used in development and by the tests.
"""

from __future__ import annotations

import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError
from sqlalchemy import Connection, text
from sqlalchemy.exc import SQLAlchemyError

from app.core.errors import DocVaultError

MIGRATIONS_ENV = "DOCVAULT_MIGRATIONS"


def migrations_directory() -> Path:
    """Return the directory holding ``env.py`` and ``versions/``."""
    override = os.environ.get(MIGRATIONS_ENV)
    if override:
        directory = Path(override).expanduser().resolve()
        if (directory / "env.py").is_file():
            return directory
        raise DocVaultError(
            "MIGRATION_FAILED",
            detail=f"{MIGRATIONS_ENV} does not point at an Alembic environment.",
        )
    directory = Path(__file__).resolve().parents[2] / "migrations"
    if (directory / "env.py").is_file():
        return directory
    raise DocVaultError(
        "MIGRATION_FAILED",
        detail="The migrations directory was not found; set DOCVAULT_MIGRATIONS.",
    )


def alembic_config(dsn: str) -> Config:
    """Build a config with the DSN supplied at runtime, never from the file."""
    directory = migrations_directory()
    config = Config(str(directory.parent / "alembic.ini"))
    config.set_main_option("script_location", str(directory))
    config.set_main_option("sqlalchemy.url", dsn)
    config.set_main_option("path_separator", "os")
    return config


def upgrade(dsn: str) -> None:
    """Apply every migration up to head."""
    try:
        command.upgrade(alembic_config(dsn), "head")
    except (CommandError, SQLAlchemyError, OSError) as exc:
        raise DocVaultError(
            "MIGRATION_FAILED",
            detail=f"Alembic upgrade failed: {exc.__class__.__name__}: {exc}",
        ) from exc


def head_revision() -> str:
    """Return the revision this build migrates to, without touching a database."""
    directory = migrations_directory()
    config = Config(str(directory.parent / "alembic.ini"))
    config.set_main_option("script_location", str(directory))
    config.set_main_option("path_separator", "os")
    head = ScriptDirectory.from_config(config).get_current_head()
    if head is None:  # pragma: no cover - a directory with no revisions
        raise DocVaultError("MIGRATION_FAILED", detail="There is no migration head.")
    return str(head)


def current_revision(connection: Connection) -> str | None:
    """Return the applied revision, or ``None`` on a database with no schema."""
    exists: object = connection.execute(
        text("SELECT to_regclass('public.alembic_version')")
    ).scalar_one()
    if exists is None:
        return None
    value = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
    return None if value is None else str(value)
