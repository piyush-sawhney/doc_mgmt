"""Read-only inspection used by ``status`` and ``doctor``.

Inspecting a vault must not take the writer lock: an operator checking a live
service should not be told the vault is busy. These functions read files and
report; they never create, unlock, or repair.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.vault import manifest
from app.vault.layout import VaultPaths, vault_paths
from app.vault.lock import LockStatus, lock_status


@dataclass(frozen=True, slots=True)
class VaultInfo:
    """Public facts about a vault, with no key material."""

    paths: VaultPaths
    manifest: manifest.Manifest
    lock: LockStatus
    blob_count: int
    audit_entries: int
    last_dump: dict[str, str] = field(default_factory=dict)
    tls_ca: Path | None = None
    tls_server: Path | None = None


def _read_latest(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    return values


def _count_audit(directory: Path) -> int:
    total = 0
    for path in directory.glob("*.jsonl"):
        if path.name == "anchors.jsonl":
            continue
        try:
            with path.open("rb") as handle:
                total += sum(1 for line in handle if line.strip())
        except OSError:
            continue
    return total


def inspect(root: Path, *, tls_directory: Path | None = None) -> VaultInfo:
    """Read the manifest, lock, blob count, audit count, and last dump."""
    paths = vault_paths(root)
    identity = manifest.validate_structure(manifest.load(paths.manifest))
    blobs = 0
    if paths.blobs.is_dir():
        blobs = sum(1 for _ in paths.blobs.rglob("*.blob"))
    ca = None
    server = None
    if tls_directory is not None:
        ca_file = tls_directory / "docvault-ca.crt"
        server_file = tls_directory / "docvault-server.crt"
        ca = ca_file if ca_file.is_file() else None
        server = server_file if server_file.is_file() else None
    return VaultInfo(
        paths=paths,
        manifest=identity,
        lock=lock_status(paths.lock),
        blob_count=blobs,
        audit_entries=_count_audit(paths.audit_dir),
        last_dump=_read_latest(paths.latest_dump),
        tls_ca=ca,
        tls_server=server,
    )
