"""Building database connections from validated configuration.

The DSN in ``docvault.toml`` never carries a password (docs/02 §6.3). The
password is read from the credential store and injected here, once, at the
process boundary. Everything downstream receives an engine that already knows
how to connect.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import NullPool

from app.core.errors import DocVaultError

SUPPORTED_MAJOR = 18
CONNECT_TIMEOUT_SECONDS = 5


@dataclass(frozen=True, slots=True)
class ServerInfo:
    """What ``doctor`` and ``init`` need to know about the server."""

    version_num: int
    version: str

    @property
    def major(self) -> int:
        return self.version_num // 10_000


def _url(dsn: str, password: str | None) -> URL:
    url = make_url(dsn)
    if password is None:
        return url
    return url.set(password=password)


def database_url(dsn: str, password: str | None = None) -> str:
    """Return a DSN with the credential injected, for Alembic and tools."""
    return _url(dsn, password).render_as_string(hide_password=False)


def create_database_engine(dsn: str, *, password: str | None = None) -> Engine:
    """Create a short-lived engine. Callers own ``dispose()``."""
    return create_engine(
        _url(dsn, password),
        poolclass=NullPool,
        connect_args={
            "connect_timeout": CONNECT_TIMEOUT_SECONDS,
            "application_name": "docvault",
        },
    )


def server_info(engine: Engine) -> ServerInfo:
    """Read the server version, mapping connection failures to ``DB_UNAVAILABLE``."""
    try:
        with engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT current_setting('server_version_num'), "
                    "current_setting('server_version')"
                )
            ).one()
    except SQLAlchemyError as exc:
        raise DocVaultError(
            "DB_UNAVAILABLE",
            detail=f"PostgreSQL could not be reached: {exc.__class__.__name__}.",
        ) from exc
    return ServerInfo(version_num=int(row[0]), version=str(row[1]))


def require_supported_server(engine: Engine) -> ServerInfo:
    """Refuse a server that is not the documented major (docs/08 §2.2)."""
    info = server_info(engine)
    if info.major != SUPPORTED_MAJOR:
        raise DocVaultError(
            "PG_VERSION_UNSUPPORTED",
            detail=f"Server {info.version} is not PostgreSQL {SUPPORTED_MAJOR}.",
        )
    return info
