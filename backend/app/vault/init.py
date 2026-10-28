"""Creating a vault from an empty directory.

This module does the vault half of ``docvault init``. Database provisioning,
TLS, and the first dump are separate steps in the same command; they are kept
out of this module so vault creation can be tested without a PostgreSQL
server.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import DocVaultError
from app.core.time import format_seconds, now_utc
from app.crypto.keys import derive_keys, new_vmk, wrap_vmk
from app.crypto.passphrase import validate_passphrase
from app.vault import audit, manifest
from app.vault.layout import atomic_write, probe_root, vault_paths

INITIAL_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class InitResult:
    """Values the operator records after ``init``."""

    root: Path
    vault_id: str
    key_fingerprint: str
    display_name: str
    created_at: str


def create_vault(
    root: Path,
    *,
    passphrase: str,
    display_name: str,
    max_file_bytes: int,
    app_version: str,
    pad_to: int = 4096,
    notes: str = "",
    schema_version: int = INITIAL_SCHEMA_VERSION,
) -> InitResult:
    """Probe the filesystem, generate the VMK, and write the vault identity.

    The passphrase is validated before any file is written. The caller is
    responsible for asking for it twice and for sealing a physical copy.
    """
    validate_passphrase(passphrase)
    paths = vault_paths(root)
    if paths.manifest.exists():
        raise DocVaultError(
            "VAULT_ALREADY_EXISTS",
            detail=f"{paths.manifest} already exists.",
        )
    probe_root(root, create=True)

    vmk = new_vmk()
    keys = derive_keys(vmk)
    wrapped = wrap_vmk(vmk, passphrase)
    created_at = format_seconds(now_utc())
    vault_id = str(uuid.uuid7())
    document = manifest.build(
        vault_id=vault_id,
        display_name=display_name,
        created_at=created_at,
        app_version=app_version,
        schema_version=schema_version,
        key_fingerprint=keys.fingerprint,
        max_file_bytes=max_file_bytes,
        pad_to=pad_to,
        notes=notes,
    )
    signed = manifest.sign(document, keys)
    validate = manifest.validate_structure(signed)
    manifest.verify(validate.raw, keys)

    wrote_kek = False
    wrote_manifest = False
    try:
        atomic_write(paths.kek, wrapped)
        wrote_kek = True
        atomic_write(paths.manifest, validate.to_bytes())
        wrote_manifest = True
        audit.append_event(
            paths.audit_dir,
            action="vault.created",
            object_type="vault",
            object_id=vault_id,
            detail={
                "display_name": display_name,
                "format_version": manifest.FORMAT_VERSION,
                "app_version": app_version,
            },
        )
    except BaseException:
        # Do not leave a directory that looks initialized but is not. A blob
        # cannot exist yet, so removing these two files is safe.
        if wrote_manifest:
            paths.manifest.unlink(missing_ok=True)
        if wrote_kek:
            paths.kek.unlink(missing_ok=True)
        raise

    return InitResult(
        root=root,
        vault_id=vault_id,
        key_fingerprint=keys.fingerprint,
        display_name=display_name,
        created_at=created_at,
    )


def read_identity(root: Path) -> manifest.Manifest:
    """Read the public manifest without a key, for ``status`` and preflight."""
    paths = vault_paths(root)
    if not paths.manifest.is_file():
        raise DocVaultError("VAULT_NOT_FOUND", detail=f"No manifest at {paths.manifest}.")
    return manifest.validate_structure(manifest.load(paths.manifest))
