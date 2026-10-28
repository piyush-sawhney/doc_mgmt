"""Liveness and readiness endpoints.

``/healthz`` answers whether the process is alive. ``/readyz`` answers whether
it can do useful work: the vault must be unlocked and, once the database layer
exists, PostgreSQL must answer. A locked vault is a ``503``, not a pretence.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.errors import DocVaultError
from app.core.http import request_id_for

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness. No authentication and no details."""
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request) -> JSONResponse:
    """Readiness: vault present and unlocked."""
    startup_error: DocVaultError | None = getattr(request.app.state, "vault_error", None)
    if startup_error is not None:
        problem = startup_error.to_problem(
            instance=request.url.path,
            request_id=request_id_for(request),
        )
        return JSONResponse(
            status_code=503,
            content=problem.model_dump(mode="json", exclude_none=False),
            media_type="application/problem+json",
        )
    vault = getattr(request.app.state, "vault", None)
    if vault is None:
        problem = DocVaultError("NOT_READY", detail="The vault is not open.").to_problem(
            instance=request.url.path,
            request_id=request_id_for(request),
        )
        return JSONResponse(
            status_code=503,
            content=problem.model_dump(mode="json", exclude_none=False),
            media_type="application/problem+json",
        )
    if vault.locked:
        problem = DocVaultError("VAULT_LOCKED").to_problem(
            instance=request.url.path,
            request_id=request_id_for(request),
        )
        return JSONResponse(
            status_code=503,
            content=problem.model_dump(mode="json", exclude_none=False),
            media_type="application/problem+json",
        )
    return JSONResponse(
        status_code=200,
        content={"status": "ready", "checks": {"vault": "unlocked"}},
    )
