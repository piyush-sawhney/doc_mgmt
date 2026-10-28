"""Request correlation and RFC 9457 exception handlers."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.errors import DocVaultError
from app.core.logging import REQUEST_ID

LOGGER = logging.getLogger(__name__)

_HTTP_CODES: dict[int, str] = {
    400: "BAD_REQUEST",
    401: "AUTH_REQUIRED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    410: "GONE",
    413: "PAYLOAD_TOO_LARGE",
    415: "UNSUPPORTED_MEDIA_TYPE",
    422: "VALIDATION_FAILED",
    423: "VAULT_LOCKED",
    429: "RATE_LIMITED",
    500: "INTERNAL_ERROR",
    503: "NOT_READY",
    504: "TIMEOUT",
    507: "STORAGE_FULL",
}


def request_id_for(request: Request) -> str:
    """Return the ID assigned by the middleware, or a fresh one outside it."""
    existing = getattr(request.state, "request_id", None)
    if isinstance(existing, str):
        return existing
    return uuid.uuid4().hex[:12].upper()


def new_request_id() -> str:
    """Opaque, sortable-ish correlation ID for a request."""
    return uuid.uuid4().hex[:12].upper()


def _problem_response(request: Request, error: DocVaultError) -> JSONResponse:
    problem = error.to_problem(instance=request.url.path, request_id=request_id_for(request))
    return JSONResponse(
        status_code=error.status,
        content=problem.model_dump(mode="json", exclude_none=False),
        media_type="application/problem+json",
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Install one mapping from domain errors to problem documents."""

    @app.exception_handler(DocVaultError)
    async def handle_docvault_error(request: Request, exc: DocVaultError) -> JSONResponse:
        if exc.status >= 500:
            LOGGER.error("request failed", extra={"code": exc.code, "path": request.url.path})
        return _problem_response(request, exc)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        fields = [
            {
                "field": ".".join(str(part) for part in item["loc"] if part != "body"),
                "code": str(item["type"]),
                "message": str(item["msg"]),
            }
            for item in exc.errors()
        ]
        return _problem_response(
            request,
            DocVaultError("VALIDATION_FAILED", fields=fields),
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _HTTP_CODES.get(exc.status_code, "INTERNAL_ERROR")
        detail = str(exc.detail) if exc.detail else None
        return _problem_response(
            request, DocVaultError(code, detail=detail, status=exc.status_code)
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, _exc: Exception) -> JSONResponse:
        LOGGER.exception("unhandled error", extra={"path": request.url.path})
        return _problem_response(request, DocVaultError("INTERNAL_ERROR"))


async def request_context_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[object]],
) -> object:
    """Assign and echo ``X-Request-Id``, and keep it in every log line."""
    incoming = request.headers.get("X-Request-Id", "").strip()
    correlation = incoming[:128] if incoming else new_request_id()
    request.state.request_id = correlation
    token = REQUEST_ID.set(correlation)
    try:
        response = await call_next(request)
    finally:
        REQUEST_ID.reset(token)
    response.headers["X-Request-Id"] = correlation  # type: ignore[attr-defined]
    return response
