"""Application factory.

Resources are created in the lifespan, not at import time, so tests can build
an app around a temporary vault and a caller can fail cleanly when the
configuration is wrong.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import health
from app.core.config import LoadedSettings, Settings, load_settings
from app.core.errors import DocVaultError
from app.core.http import register_exception_handlers, request_context_middleware
from app.core.logging import configure_logging
from app.vault.session import VaultManager
from app.version import APP_NAME, __version__

LOGGER = logging.getLogger(__name__)


def create_app(
    settings: Settings | None = None,
    *,
    loaded: LoadedSettings | None = None,
    vault: VaultManager | None = None,
    app_version: str = __version__,
) -> FastAPI:
    """Build the ASGI application around validated settings.

    If no settings are supplied, ``DOCVAULT_CONFIG`` (or the OS default path) is
    read now, so a bad configuration fails before the server binds a port.
    """
    if loaded is None:
        loaded = load_settings() if settings is None else LoadedSettings(settings=settings)
    active = loaded.settings
    configure_logging(active.log.level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        manager: VaultManager | None = vault
        try:
            if manager is None:
                root = active.require_vault_root()
                manager = VaultManager(root, app_version=app_version)
            manager.open()
        except DocVaultError as exc:
            # Liveness stays up so an operator can read /readyz and doctor.
            app.state.vault_error = exc
            LOGGER.error("vault did not open at startup", extra={"code": exc.code})
        app.state.vault = manager
        try:
            yield
        finally:
            if manager is not None:
                manager.close()

    app = FastAPI(
        title=APP_NAME,
        version=app_version,
        lifespan=lifespan,
        docs_url="/api/docs" if active.is_development else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if active.is_development else None,
    )
    app.state.settings = active
    app.state.vault = None
    app.state.vault_error = None
    app.middleware("http")(request_context_middleware)
    register_exception_handlers(app)
    app.include_router(health.router)
    return app
