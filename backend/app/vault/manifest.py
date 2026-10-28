"""Readable, signed ``manifest.json``.

The manifest is not secret: it names the vault, its format, and its key
fingerprint. It is signed with a key derived from the VMK, which is why the
signature can only be checked after unlock. Unknown fields are preserved so a
newer application can add one without an older one deleting it.
"""

from __future__ import annotations

import copy
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.errors import DocVaultError
from app.crypto.canonical import b64url_encode, canonical_json, sha256_hex
from app.crypto.keys import VaultKeys

FORMAT: str = "docvault.vault"
FORMAT_VERSION: int = 1
BLOB_FORMAT: str = "DVC1"
BLOB_VERSION: int = 1
INTEGRITY_ALG: str = "hmac-sha256"

_REQUIRED_TOP_LEVEL = frozenset(
    {
        "format",
        "format_version",
        "vault_id",
        "display_name",
        "created_at",
        "created_by_app",
        "schema_version",
        "key_wrap",
        "key_fingerprint",
        "blob",
        "paths",
        "limits",
        "integrity",
    }
)


@dataclass(frozen=True, slots=True)
class Manifest:
    """A validated manifest with typed accessors over the raw document."""

    raw: dict[str, Any]

    @property
    def vault_id(self) -> str:
        return str(self.raw["vault_id"])

    @property
    def display_name(self) -> str:
        return str(self.raw["display_name"])

    @property
    def format_version(self) -> int:
        return int(self.raw["format_version"])

    @property
    def schema_version(self) -> int:
        return int(self.raw["schema_version"])

    @property
    def key_fingerprint(self) -> str:
        return str(self.raw["key_fingerprint"])

    @property
    def max_file_bytes(self) -> int:
        return int(self.raw["limits"]["max_file_bytes"])

    @property
    def pad_to(self) -> int:
        return int(self.raw["blob"]["pad_to"])

    @property
    def fanout(self) -> tuple[int, int]:
        first, second = self.raw["blob"]["fanout"]
        return int(first), int(second)

    def to_bytes(self) -> bytes:
        """Pretty JSON for humans; the signature covers the canonical form."""
        return (json.dumps(self.raw, indent=2, ensure_ascii=False) + "\n").encode("utf-8")

    def with_schema_version(self, schema_version: int) -> Manifest:
        raw = copy.deepcopy(self.raw)
        raw["schema_version"] = schema_version
        return Manifest(raw=raw)


def _signature_payload(manifest: dict[str, Any]) -> bytes:
    payload = copy.deepcopy(manifest)
    payload.pop("integrity", None)
    return canonical_json(payload)


def sign(manifest: dict[str, Any], keys: VaultKeys) -> dict[str, Any]:
    """Return a copy with ``integrity`` recomputed."""
    signed = copy.deepcopy(manifest)
    signature = hmac.new(
        keys.manifest_key,
        _signature_payload(signed),
        "sha256",
    ).digest()
    signed["integrity"] = {"alg": INTEGRITY_ALG, "sig": b64url_encode(signature)}
    return signed


def verify(manifest: dict[str, Any], keys: VaultKeys) -> None:
    """Check the HMAC over the canonical object without ``integrity``."""
    integrity = manifest.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("alg") != INTEGRITY_ALG:
        raise DocVaultError(
            "VAULT_MANIFEST_TAMPERED",
            detail="The manifest has no supported integrity record.",
        )
    presented = str(integrity.get("sig", ""))
    expected = b64url_encode(
        hmac.new(keys.manifest_key, _signature_payload(manifest), "sha256").digest()
    )
    if not hmac.compare_digest(expected.encode("ascii"), presented.encode("ascii")):
        raise DocVaultError(
            "VAULT_MANIFEST_TAMPERED",
            detail="The manifest signature does not match its contents.",
        )


def validate_structure(manifest: dict[str, Any]) -> Manifest:
    """Check the format contract and return a typed view."""
    missing = sorted(_REQUIRED_TOP_LEVEL - manifest.keys())
    if missing:
        raise DocVaultError(
            "VAULT_MANIFEST_INVALID",
            detail=f"The manifest is missing: {', '.join(missing)}.",
        )
    if manifest["format"] != FORMAT:
        raise DocVaultError(
            "VAULT_MANIFEST_INVALID", detail="The manifest format is not docvault.vault."
        )
    if manifest["format_version"] != FORMAT_VERSION:
        raise DocVaultError(
            "VAULT_MANIFEST_INVALID",
            detail=f"Unsupported vault format version {manifest['format_version']}.",
        )
    blob = manifest["blob"]
    if blob.get("format") != BLOB_FORMAT:
        raise DocVaultError("VAULT_MANIFEST_INVALID", detail="The blob format is not DVC1.")
    if blob.get("version") != BLOB_VERSION:
        raise DocVaultError("VAULT_MANIFEST_INVALID", detail="The blob version is unsupported.")
    if blob.get("address") != "hmac-sha256":
        raise DocVaultError(
            "VAULT_MANIFEST_INVALID", detail="The address algorithm is unsupported."
        )
    fanout = blob.get("fanout")
    if not isinstance(fanout, list) or fanout != [2, 2]:
        raise DocVaultError("VAULT_MANIFEST_INVALID", detail="The fan-out must be [2, 2].")
    pad_to = blob.get("pad_to")
    if not isinstance(pad_to, int) or pad_to < 0 or pad_to > 1024 * 1024:
        raise DocVaultError("VAULT_MANIFEST_INVALID", detail="blob.pad_to is out of range.")
    if not isinstance(manifest["limits"].get("max_file_bytes"), int):
        raise DocVaultError(
            "VAULT_MANIFEST_INVALID", detail="limits.max_file_bytes is not an integer."
        )
    return Manifest(raw=manifest)


def build(
    *,
    vault_id: str,
    display_name: str,
    created_at: str,
    app_version: str,
    schema_version: int,
    key_fingerprint: str,
    max_file_bytes: int,
    pad_to: int = 4096,
    notes: str = "",
) -> dict[str, Any]:
    """Build an unsigned manifest document."""
    return {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "vault_id": vault_id,
        "display_name": display_name,
        "created_at": created_at,
        "created_by_app": app_version,
        "schema_version": schema_version,
        "key_wrap": "keys/kek.wrapped",
        "key_fingerprint": key_fingerprint,
        "blob": {
            "format": BLOB_FORMAT,
            "version": BLOB_VERSION,
            "address": "hmac-sha256",
            "address_prefix": "docvault/blobaddr/v1",
            "fanout": [2, 2],
            "pad_to": pad_to,
        },
        "paths": {
            "blobs": "blobs",
            "dump": "index/db",
            "audit": "audit",
            "journal": "journal",
            "keys": "keys",
            "tmp": "tmp",
        },
        "limits": {"max_file_bytes": max_file_bytes},
        "notes": notes,
    }


def load(path: Path) -> dict[str, Any]:
    """Read and parse a manifest; does not verify its signature."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DocVaultError("VAULT_NOT_FOUND", detail=f"Cannot read {path}: {exc}") from exc
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DocVaultError("VAULT_MANIFEST_INVALID", detail=f"{path} is not valid JSON.") from exc
    if not isinstance(parsed, dict):
        raise DocVaultError("VAULT_MANIFEST_INVALID", detail="The manifest root is not an object.")
    return parsed


def load_and_verify(path: Path, keys: VaultKeys) -> Manifest:
    """Load, check structure, check the fingerprint, then verify the HMAC.

    The fingerprint is checked first on purpose: a valid passphrase for the
    wrong vault produces *two* failures, and "wrong key" is the actionable one
    (docs/05 §8.2). A tampered fingerprint is still refused; only the label
    changes, not the outcome.
    """
    manifest = validate_structure(load(path))
    if not hmac.compare_digest(manifest.key_fingerprint, keys.fingerprint):
        raise DocVaultError(
            "VAULT_KEY_MISMATCH",
            detail="The derived key does not belong to this manifest.",
        )
    verify(manifest.raw, keys)
    return manifest


def description_hash(manifest: Manifest) -> str:
    """Stable digest for diagnostics and the dump pointer."""
    return sha256_hex(canonical_json(manifest.raw))
