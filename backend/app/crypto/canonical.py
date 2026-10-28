"""Canonical JSON and small encoding helpers shared by signing and hashing."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    """Return the canonical byte form used for signatures and audit hashes.

    UTF-8, keys sorted, no insignificant whitespace, and no NaN/Infinity.
    """
    text = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Lower-case hex SHA-256."""
    return hashlib.sha256(data).hexdigest()


def b64url_encode(data: bytes) -> str:
    """Unpadded base64url, used in the manifest signature field."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Inverse of :func:`b64url_encode`."""
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)
