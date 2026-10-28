"""Domain errors and the RFC 9457 problem-document shape.

The error code is the stable part. Clients switch on ``code``; humans read
``detail`` and ``remediation``. HTTP status is a transport detail derived from
the code so the same failure maps consistently everywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

PROBLEM_BASE = "https://docvault.local/problems"


@dataclass(frozen=True, slots=True)
class ErrorSpec:
    """Static description of one error code."""

    title: str
    status: int
    detail: str
    remediation: str = ""


# Kept in one place so the CLI, the API, and the tests cannot drift.
ERROR_SPECS: dict[str, ErrorSpec] = {
    # Configuration and environment
    "CONFIG_MISSING": ErrorSpec(
        "Configuration not found",
        500,
        "The configuration file does not exist.",
        "Set DOCVAULT_CONFIG or install docvault.toml in the OS config folder.",
    ),
    "CONFIG_INVALID": ErrorSpec(
        "Configuration is invalid",
        500,
        "The configuration file could not be validated.",
        "Fix the named key; unknown keys are rejected to catch typos.",
    ),
    "DB_NOT_LOOPBACK": ErrorSpec(
        "Database is not on loopback",
        503,
        "The database address is not a loopback address.",
        "Point the DSN at 127.0.0.1 or a local socket (02 §6.3).",
    ),
    "DB_UNAVAILABLE": ErrorSpec(
        "Database unavailable",
        503,
        "PostgreSQL could not be reached.",
        "Start PostgreSQL and check the DSN.",
    ),
    "DB_CREDENTIAL_UNREADABLE": ErrorSpec(
        "Database credential unreadable",
        503,
        "The stored database credential could not be decrypted.",
        "Run docvault init --reuse-vault as the service account.",
    ),
    "PG_VERSION_UNSUPPORTED": ErrorSpec(
        "PostgreSQL version unsupported",
        503,
        "The server major version is not 18.",
        "Install PostgreSQL 18; the application does not run on another major.",
    ),
    "PG_CLIENT_MISSING": ErrorSpec(
        "PostgreSQL client tools missing",
        503,
        "pg_dump or pg_restore was not found.",
        "Install the client tools or set database.pg_bin_dir.",
    ),
    "PG_CLIENT_TOO_OLD": ErrorSpec(
        "PostgreSQL client tools too old",
        503,
        "pg_dump is older than the server.",
        "Use the client tools shipped with PostgreSQL 18.",
    ),
    "SEED_CONFLICT": ErrorSpec(
        "Seeded catalogue conflict",
        409,
        "A seeded code already exists with a different position in the type tree.",
        "Rename or remove the conflicting row, then run the seed again.",
    ),
    "SEED_FAILED": ErrorSpec(
        "Seeded catalogue could not be written",
        500,
        "The document-type catalogue could not be inserted.",
        "Check the database permissions and run the seed again.",
    ),
    "SCHEMA_TOO_NEW": ErrorSpec(
        "Database schema is newer than the application",
        503,
        "The database has been migrated by a newer application version.",
        "Install the matching application version or restore its dump.",
    ),
    "MIGRATION_FAILED": ErrorSpec(
        "Database migration failed",
        500,
        "The schema could not be migrated.",
        "Read the reported cause, fix it, and run docvault migrate again.",
    ),
    # Filesystem
    "FS_NETWORK_PATH": ErrorSpec(
        "Vault is on a network filesystem",
        503,
        "The vault path resolves to a network or FUSE filesystem.",
        "Move the vault to a local native disk (03 §7).",
    ),
    "FS_NO_ATOMIC_RENAME": ErrorSpec(
        "Filesystem cannot rename atomically",
        503,
        "The atomic rename probe failed.",
        "Use a local NTFS or ext4 volume and check permissions.",
    ),
    "FS_NO_FSYNC": ErrorSpec(
        "Filesystem cannot flush to disk",
        503,
        "fsync on a file or directory failed.",
        "Use a local native filesystem; do not use a synced folder.",
    ),
    "FS_UNRELIABLE_CASING": ErrorSpec(
        "Filesystem folds case unpredictably",
        503,
        "Two names differing only by case collided.",
        "Use a local native filesystem with stable case behaviour.",
    ),
    "FS_SYMLINK": ErrorSpec(
        "Vault path is a symlink",
        503,
        "A symlink was found in the vault path.",
        "Point vault.root at the real directory, not a link.",
    ),
    "VAULT_UNWRITABLE": ErrorSpec(
        "Vault is not writable",
        503,
        "The vault directory cannot be written by this process.",
        "Fix ownership and permissions on the vault directory.",
    ),
    # Vault lifecycle
    "VAULT_NOT_FOUND": ErrorSpec(
        "Vault not found",
        503,
        "No manifest.json was found at the configured vault root.",
        "Run docvault init --vault <path> or fix vault.root.",
    ),
    "VAULT_ALREADY_EXISTS": ErrorSpec(
        "Vault already exists",
        409,
        "The target directory already contains a vault manifest.",
        "Use a different path, or init --reuse-vault to repair credentials.",
    ),
    "VAULT_LOCKED": ErrorSpec(
        "Vault is locked",
        423,
        "The vault key is not in memory.",
        "Run docvault unlock on the host.",
    ),
    "VAULT_LOCKED_BY_OTHER": ErrorSpec(
        "Vault is in use",
        423,
        "Another process holds the vault lock.",
        "Stop the other process. Use --force only if you know it is dead.",
    ),
    "VAULT_KEY_MISMATCH": ErrorSpec(
        "Wrong key for this vault",
        503,
        "The derived key fingerprint does not match the manifest.",
        "Check that vault.root points at the intended vault.",
    ),
    "VAULT_MANIFEST_TAMPERED": ErrorSpec(
        "Manifest integrity check failed",
        503,
        "The manifest signature does not verify.",
        "Stop and restore the vault from a known-good backup.",
    ),
    "VAULT_DB_MISMATCH": ErrorSpec(
        "Vault and database do not match",
        503,
        "The vault_id in the database differs from the manifest.",
        "Attach the database that belongs to this vault.",
    ),
    "VAULT_MANIFEST_INVALID": ErrorSpec(
        "Manifest is invalid",
        503,
        "The manifest does not match the vault format.",
        "Restore manifest.json from a backup.",
    ),
    "VAULT_INVALID": ErrorSpec(
        "Vault path is invalid",
        500,
        "The vault path or derived path is not usable.",
        "Use an absolute path to a local directory.",
    ),
    "BAD_PASSPHRASE": ErrorSpec(
        "Incorrect passphrase or damaged key file",
        401,
        "The key file could not be unwrapped.",
        "Try again; after five failures the application backs off.",
    ),
    "PASSPHRASE_POLICY": ErrorSpec(
        "Passphrase does not meet policy",
        422,
        "The passphrase is too short, too common, or too predictable.",
        "Use at least 12 characters and avoid common phrases (05 §8.1).",
    ),
    "PASSPHRASE_MISMATCH": ErrorSpec(
        "Passphrases do not match",
        422,
        "The two passphrases differ.",
        "Type the same passphrase twice.",
    ),
    # Storage integrity
    "BLOB_INVALID": ErrorSpec(
        "Blob is not a valid DVC1 container",
        500,
        "The blob header or length is invalid.",
        "Quarantine the blob and restore it from a backup.",
    ),
    "BLOB_KEY_MISMATCH": ErrorSpec(
        "Blob belongs to another vault",
        500,
        "The blob key identifier does not match this vault.",
        "Check that vault.root points at the intended vault.",
    ),
    "BLOB_TAMPERED": ErrorSpec(
        "Blob authentication failed",
        500,
        "The blob ciphertext did not authenticate.",
        "Quarantine the blob; do not attempt a best-effort read.",
    ),
    "BLOB_ADDRESS_MISMATCH": ErrorSpec(
        "Blob address does not match its content",
        500,
        "The recomputed content address differs from the filename.",
        "Quarantine the blob and investigate the copy that produced it.",
    ),
    "COLUMN_TAMPERED": ErrorSpec(
        "Encrypted column failed authentication",
        500,
        "The database column did not decrypt under its table and column AAD.",
        "Restore the row from a dump; do not edit ciphertext by hand.",
    ),
    "AUDIT_CHAIN_BROKEN": ErrorSpec(
        "Audit chain is broken",
        500,
        "The newest audit entry is missing, partial, or unreadable.",
        "Run docvault verify and restore the audit folder from a backup.",
    ),
    # Generic API errors
    "BAD_REQUEST": ErrorSpec("Bad request", 400, "The request could not be parsed."),
    "AUTH_REQUIRED": ErrorSpec("Authentication required", 401, "No valid session was presented."),
    "METHOD_NOT_ALLOWED": ErrorSpec(
        "Method not allowed", 405, "That method is not supported here."
    ),
    "CONFLICT": ErrorSpec("Conflict", 409, "The resource changed while you were editing it."),
    "GONE": ErrorSpec("Gone", 410, "The ticket expired or was already used."),
    "PAYLOAD_TOO_LARGE": ErrorSpec("Payload too large", 413, "The upload exceeds the limit."),
    "UNSUPPORTED_MEDIA_TYPE": ErrorSpec(
        "Unsupported media type", 415, "That file type is not accepted."
    ),
    "RATE_LIMITED": ErrorSpec("Too many requests", 429, "Slow down and retry."),
    "NOT_READY": ErrorSpec("Not ready", 503, "A dependency is not ready."),
    "TIMEOUT": ErrorSpec("Timed out", 504, "The operation exceeded its time budget."),
    "STORAGE_FULL": ErrorSpec("Storage is full", 507, "Free space on the vault volume."),
    "NOT_FOUND": ErrorSpec("Not found", 404, "The requested resource was not found."),
    "FORBIDDEN": ErrorSpec("Not allowed", 403, "You do not have the required capability."),
    "PRINT_RESTRICTED": ErrorSpec(
        "Printing is restricted",
        403,
        "This restricted document needs an explicit print grant on the document.",
        "Ask an administrator for a per-document print grant (13 §6).",
    ),
    "VALIDATION_FAILED": ErrorSpec("Validation failed", 422, "One or more fields are invalid."),
    "INTERNAL_ERROR": ErrorSpec(
        "Internal error",
        500,
        "An unexpected error occurred.",
        "Quote the request ID when reporting this.",
    ),
}


class DocVaultError(Exception):
    """A failure with a stable code and an operator-facing remedy."""

    def __init__(
        self,
        code: str,
        *,
        detail: str | None = None,
        remediation: str | None = None,
        status: int | None = None,
        fields: list[dict[str, str]] | None = None,
    ) -> None:
        spec = ERROR_SPECS.get(code)
        if spec is None:
            spec = ErrorSpec("Error", 500, "An error occurred.")
        self.code = code
        self.title = spec.title
        self.status = status if status is not None else spec.status
        self.detail = detail if detail is not None else spec.detail
        self.remediation = remediation if remediation is not None else spec.remediation
        self.fields = fields or []
        super().__init__(f"{code}: {self.detail}")

    def to_problem(self, *, instance: str, request_id: str) -> Problem:
        return Problem(
            type=f"{PROBLEM_BASE}/{self.code.lower().replace('_', '-')}",
            title=self.title,
            status=self.status,
            detail=self.detail,
            instance=instance,
            request_id=request_id,
            code=self.code,
            remediation=self.remediation or None,
            errors=[FieldError(**item) for item in self.fields],
        )


class Problem(BaseModel):
    """RFC 9457 problem document with DocVault's stable extension members."""

    model_config = ConfigDict(extra="forbid")

    type: str
    title: str
    status: int
    detail: str
    instance: str
    request_id: str
    code: str
    remediation: str | None = None
    errors: list[FieldError] = Field(default_factory=list)


class FieldError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str
    code: str
    message: str


@dataclass(slots=True)
class Context:
    """Per-request values used when turning an exception into a problem."""

    instance: str
    request_id: str
    extra: dict[str, Any] = field(default_factory=dict)
