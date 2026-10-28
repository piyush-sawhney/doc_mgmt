"""The process-local vault session.

One process holds one lock, one manifest, and (when unlocked) one key set.
Nothing here writes the passphrase or the VMK to disk. The API and the CLI
share this class so there is one unlock path, not two.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import DocVaultError
from app.crypto.keys import VaultKeys, derive_keys, unwrap_vmk
from app.vault import audit
from app.vault import manifest as vault_manifest
from app.vault.layout import VaultPaths, probe_root, vault_paths
from app.vault.lock import LockStatus, VaultLock, lock_status

UNLOCK_WINDOW_SECONDS = 300.0
UNLOCK_MAX_ATTEMPTS = 5
UNLOCK_MAX_DELAY_SECONDS = 60.0


@dataclass(frozen=True, slots=True)
class VaultStatus:
    """Safe-to-print status; contains no key material."""

    root: Path
    vault_id: str
    display_name: str
    key_fingerprint: str
    format_version: int
    schema_version: int
    locked: bool
    lock: LockStatus


class UnlockThrottle:
    """In-memory exponential back-off after repeated wrong passphrases.

    The counter resets on success. It is deliberately process-local: a restart
    is already an operator action on the host, and persisting it would create
    a lockout that a legitimate custodian cannot clear.
    """

    def __init__(self) -> None:
        self._failures = 0
        self._not_before = 0.0

    def check(self) -> None:
        waiting = self._not_before - time.monotonic()
        if waiting > 0:
            raise DocVaultError(
                "BAD_PASSPHRASE",
                detail=f"Too many attempts. Wait {waiting:.0f} seconds and try again.",
            )

    def fail(self) -> None:
        self._failures += 1
        if self._failures >= UNLOCK_MAX_ATTEMPTS:
            delay = min(
                2.0 ** (self._failures - UNLOCK_MAX_ATTEMPTS),
                UNLOCK_MAX_DELAY_SECONDS,
            )
            self._not_before = time.monotonic() + delay

    def succeed(self) -> None:
        self._failures = 0
        self._not_before = 0.0


class VaultManager:
    """Own the vault lock and the in-memory key set for one process."""

    def __init__(
        self,
        root: Path,
        *,
        app_version: str,
        force_lock: bool = False,
    ) -> None:
        self._root = root
        self._app_version = app_version
        self._force_lock = force_lock
        self._paths: VaultPaths | None = None
        self._manifest: vault_manifest.Manifest | None = None
        self._keys: VaultKeys | None = None
        self._lock: VaultLock | None = None
        self._mutex = threading.RLock()
        self._throttle = UnlockThrottle()

    @property
    def paths(self) -> VaultPaths:
        if self._paths is None:
            raise DocVaultError("VAULT_NOT_FOUND", detail="The vault has not been opened.")
        return self._paths

    @property
    def manifest(self) -> vault_manifest.Manifest:
        if self._manifest is None:
            raise DocVaultError("VAULT_NOT_FOUND", detail="The vault has not been opened.")
        return self._manifest

    @property
    def locked(self) -> bool:
        return self._keys is None

    @property
    def keys(self) -> VaultKeys:
        keys = self._keys
        if keys is None:
            raise DocVaultError("VAULT_LOCKED")
        return keys

    def open(self) -> VaultManager:
        """Probe the vault, read its public identity, and take the lock."""
        with self._mutex:
            if self._paths is not None:
                return self
            paths = vault_paths(self._root)
            if not paths.manifest.is_file():
                raise DocVaultError("VAULT_NOT_FOUND", detail=f"No manifest at {paths.manifest}.")
            probe_root(self._root, create=False)
            identity = vault_manifest.validate_structure(vault_manifest.load(paths.manifest))
            lock = VaultLock(
                paths,
                vault_id=identity.vault_id,
                app_version=self._app_version,
                force=self._force_lock,
            ).acquire()
            self._paths = paths
            self._manifest = identity
            self._lock = lock
            return self

    def unlock(self, passphrase: str) -> vault_manifest.Manifest:
        """Unwrap the VMK, derive sub-keys, and verify the manifest."""
        with self._mutex:
            if self._paths is None:
                self.open()
            self._throttle.check()
            try:
                wrapped = self.paths.kek.read_bytes()
            except OSError as exc:
                self._throttle.fail()
                raise DocVaultError(
                    "BAD_PASSPHRASE", detail="The key file cannot be read."
                ) from exc
            try:
                vmk = unwrap_vmk(wrapped, passphrase)
                keys = derive_keys(vmk)
                identity = vault_manifest.load_and_verify(self.paths.manifest, keys)
            except DocVaultError as exc:
                self._throttle.fail()
                audit.append_event(
                    self.paths.audit_dir,
                    action="vault.unlock.deny",
                    object_type="vault",
                    object_id=self.manifest.vault_id,
                    outcome="deny",
                    detail={"reason": exc.code},
                )
                raise
            self._keys = keys
            self._manifest = identity
            self._throttle.succeed()
            audit.append_event(
                self.paths.audit_dir,
                action="vault.unlock.allow",
                object_type="vault",
                object_id=identity.vault_id,
                detail={"key_fingerprint": identity.key_fingerprint},
            )
            return identity

    def lock(self) -> None:
        """Drop the key material from memory, keeping the process alive."""
        with self._mutex:
            if self._keys is None:
                return
            self._keys = None
            if self._paths is not None and self._manifest is not None:
                audit.append_event(
                    self._paths.audit_dir,
                    action="vault.lock",
                    object_type="vault",
                    object_id=self._manifest.vault_id,
                )

    def close(self) -> None:
        """Release the writer lock. Safe to call twice."""
        with self._mutex:
            self._keys = None
            if self._lock is not None:
                self._lock.release()
                self._lock = None
            self._paths = None
            self._manifest = None

    def status(self) -> VaultStatus:
        """Return status without requiring an unlocked vault."""
        with self._mutex:
            if self._paths is None:
                self.open()
            identity = self.manifest
            status = lock_status(self.paths.lock)
            return VaultStatus(
                root=self._root,
                vault_id=identity.vault_id,
                display_name=identity.display_name,
                key_fingerprint=identity.key_fingerprint,
                format_version=identity.format_version,
                schema_version=identity.schema_version,
                locked=self.locked,
                lock=status,
            )

    def record_event(
        self,
        action: str,
        *,
        actor_id: str | None = None,
        object_type: str | None = None,
        object_id: str | None = None,
        outcome: str = "allow",
        source_ip: str | None = None,
        detail: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Append an audit event through the open vault."""
        if self._paths is None:
            self.open()
        return audit.append_event(
            self.paths.audit_dir,
            action=action,
            actor_id=actor_id,
            object_type=object_type,
            object_id=object_id,
            outcome=outcome,
            source_ip=source_ip,
            detail=dict(detail or {}),
        )

    def __enter__(self) -> VaultManager:
        return self.open()

    def __exit__(self, *_exc: object) -> None:
        self.close()
