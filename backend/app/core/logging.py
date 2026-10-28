"""Structured logging with a request identifier on every line.

Logs are JSON lines so a Windows Event Log collector and a Linux journal both
keep the fields intact. The formatter never receives the vault passphrase:
callers must not pass it, and the redaction filter drops common secret keys if
they appear in ``extra``.
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

REQUEST_ID: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

_SECRET_KEYS = frozenset(
    {"passphrase", "password", "token", "secret", "api_key", "authorization", "cookie"}
)
_RESERVED = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
    "message",
    "asctime",
    "taskName",
}


def current_request_id() -> str:
    """Return the request ID for the current task, or ``-`` outside a request."""
    return REQUEST_ID.get()


class JsonFormatter(logging.Formatter):
    """Render one log record as a single JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": current_request_id(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            if key in _SECRET_KEYS:
                payload[key] = "[redacted]"
                continue
            if isinstance(value, str | int | float | bool) or value is None:
                payload[key] = value
            else:
                payload[key] = repr(value)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logging(level: str = "info", *, stream: Any = None) -> None:
    """Install one JSON handler on the root logger.

    Idempotent, so tests and repeated app factories do not stack handlers.
    """
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level.upper())
    # uvicorn installs its own handlers; let its records flow through ours.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
