"""Creating the application role and database.

Everything here runs over the operator's admin connection, never the app's.
The app role is deliberately unprivileged: no superuser, no ``CREATEDB``, no
``CREATEROLE``. It owns its database, which is enough to create the trusted
``citext`` extension the schema needs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import NullPool

from app.core.errors import DocVaultError

IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
DEFAULT_DATABASE = "docvault"
DEFAULT_ROLE = "docvault_app"


@dataclass(frozen=True, slots=True)
class ProvisionResult:
    database: str
    role: str
    role_created: bool
    database_created: bool


def _identifier(value: str, label: str) -> str:
    if not IDENTIFIER.match(value):
        raise DocVaultError(
            "CONFIG_INVALID",
            detail=f"{label} {value!r} is not a safe PostgreSQL identifier.",
        )
    return value


def provision(
    admin_dsn: str,
    *,
    database: str = DEFAULT_DATABASE,
    role: str = DEFAULT_ROLE,
    password: str,
) -> ProvisionResult:
    """Create or adopt the role and database. Safe to run twice."""
    _identifier(database, "database name")
    _identifier(role, "role name")
    engine = create_engine(admin_dsn, isolation_level="AUTOCOMMIT", poolclass=NullPool)
    try:
        with engine.connect() as connection:
            quoted_password = str(
                connection.execute(
                    text("SELECT quote_literal(:password)"), {"password": password}
                ).scalar_one()
            )
            role_created = (
                connection.execute(
                    text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role}
                ).scalar_one_or_none()
                is None
            )
            if role_created:
                connection.execute(
                    text(
                        f'CREATE ROLE "{role}" LOGIN NOSUPERUSER NOCREATEDB '
                        f"NOCREATEROLE PASSWORD {quoted_password}"
                    )
                )
            else:
                connection.execute(
                    text(
                        f'ALTER ROLE "{role}" LOGIN NOSUPERUSER NOCREATEDB '
                        f"NOCREATEROLE PASSWORD {quoted_password}"
                    )
                )

            database_created = (
                connection.execute(
                    text("SELECT 1 FROM pg_database WHERE datname = :database"),
                    {"database": database},
                ).scalar_one_or_none()
                is None
            )
            if database_created:
                connection.execute(text(f'CREATE DATABASE "{database}" OWNER "{role}"'))
            else:
                connection.execute(text(f'ALTER DATABASE "{database}" OWNER TO "{role}"'))
    except SQLAlchemyError as exc:
        raise DocVaultError(
            "DB_UNAVAILABLE",
            detail=f"Could not provision the database: {exc.__class__.__name__}: {exc}",
            remediation="Check the admin DSN and that the server is PostgreSQL 18.",
        ) from exc
    finally:
        engine.dispose()

    return ProvisionResult(
        database=database,
        role=role,
        role_created=role_created,
        database_created=database_created,
    )
