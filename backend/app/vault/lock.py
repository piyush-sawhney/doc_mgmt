"""Single-writer ``.lock`` guard.

Two backends writing one vault is the most destructive failure in the system.
The lock is advisory, not a security boundary: it stops the accident, not a
determined operator. A heartbeat lets a later start distinguish a clean crash
from a live process.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import platform
import socket
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from app.core.errors import DocVaultError
from app.core.time import format_seconds, now_utc, parse_timestamp
from app.vault import audit
from app.vault.layout import VaultPaths

LOGGER = logging.getLogger(__name__)

HEARTBEAT_SECONDS = 5.0
STALE_SECONDS = 30.0


def host_id() -> str:
    """A stable, non-secret identifier for this machine."""
    material = f"{platform.node()}|{uuid.getnode()}|{socket.gethostname()}".encode()
    return f"sha256:{hashlib.sha256(material).hexdigest()}"


@dataclass(frozen=True, slots=True)
class LockRecord:
    """The on-disk lock document."""

    instance_id: str
    vault_id: str
    host_id: str
    pid: int
    app_version: str
    started_at: datetime
    heartbeat_at: datetime

    @property
    def age_seconds(self) -> float:
        return (now_utc() - self.heartbeat_at).total_seconds()

    def to_json(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "vault_id": self.vault_id,
            "host_id": self.host_id,
            "pid": self.pid,
            "app_version": self.app_version,
            "started_at": format_seconds(self.started_at),
            "heartbeat_at": format_seconds(self.heartbeat_at),
        }


@dataclass(frozen=True, slots=True)
class LockStatus:
    """What ``status`` and the takeover decision need."""

    record: LockRecord | None
    stale: bool

    @property
    def held(self) -> bool:
        return self.record is not None


def read_lock(path: Path) -> LockRecord | None:
    """Read and validate a lock file, or return ``None`` if it is unreadable."""
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    try:
        return LockRecord(
            instance_id=str(parsed["instance_id"]),
            vault_id=str(parsed["vault_id"]),
            host_id=str(parsed["host_id"]),
            pid=int(parsed["pid"]),
            app_version=str(parsed["app_version"]),
            started_at=parse_timestamp(str(parsed["started_at"])),
            heartbeat_at=parse_timestamp(str(parsed["heartbeat_at"])),
        )
    except (KeyError, TypeError, ValueError):
        return None


def lock_status(path: Path) -> LockStatus:
    record = read_lock(path)
    return LockStatus(
        record=record, stale=record is not None and record.age_seconds > STALE_SECONDS
    )


class VaultLock:
    """Acquire, heartbeat, and release one vault lock."""

    def __init__(
        self,
        paths: VaultPaths,
        *,
        vault_id: str,
        app_version: str,
        force: bool = False,
    ) -> None:
        self._paths = paths
        self._vault_id = vault_id
        self._app_version = app_version
        self._force = force
        self._record: LockRecord | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def record(self) -> LockRecord | None:
        return self._record

    def acquire(self) -> VaultLock:
        existing = lock_status(self._paths.lock)
        if existing.record is not None:
            if not self._force:
                reason = (
                    "The previous writer's heartbeat is stale; use --force only if it is dead."
                    if existing.stale
                    else "Another process holds the lock."
                )
                raise DocVaultError("VAULT_LOCKED_BY_OTHER", detail=reason)
            audit.append_event(
                self._paths.audit_dir,
                action="vault.lock.forced",
                object_type="vault",
                object_id=self._vault_id,
                outcome="allow",
                detail={
                    "stale": existing.stale,
                    "previous_instance_id": existing.record.instance_id,
                    "previous_pid": existing.record.pid,
                },
            )
            LOGGER.warning("taking over a vault lock", extra={"previous_pid": existing.record.pid})
            with contextlib.suppress(OSError):
                self._paths.lock.unlink()

        now = now_utc()
        record = LockRecord(
            instance_id=str(uuid.uuid7()),
            vault_id=self._vault_id,
            host_id=host_id(),
            pid=os.getpid(),
            app_version=self._app_version,
            started_at=now,
            heartbeat_at=now,
        )
        payload = json.dumps(record.to_json(), indent=2, sort_keys=True) + "\n"
        try:
            descriptor = os.open(
                self._paths.lock,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError as exc:
            raise DocVaultError("VAULT_LOCKED_BY_OTHER") from exc
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            with contextlib.suppress(OSError):
                self._paths.lock.unlink()
            raise
        self._record = record
        self._start_heartbeat()
        return self

    def _write_heartbeat(self) -> None:
        if self._record is None:
            return
        record = LockRecord(
            instance_id=self._record.instance_id,
            vault_id=self._record.vault_id,
            host_id=self._record.host_id,
            pid=self._record.pid,
            app_version=self._record.app_version,
            started_at=self._record.started_at,
            heartbeat_at=now_utc(),
        )
        temporary = self._paths.root / f".lock.{uuid.uuid4().hex}.part"
        try:
            temporary.write_text(
                json.dumps(record.to_json(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            if os.name == "posix":
                temporary.chmod(0o600)
            temporary.replace(self._paths.lock)
        except OSError:
            LOGGER.exception("could not refresh the vault lock heartbeat")
            with contextlib.suppress(OSError):
                temporary.unlink(missing_ok=True)
            return
        self._record = record

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(HEARTBEAT_SECONDS):
            self._write_heartbeat()

    def _start_heartbeat(self) -> None:
        self._thread = threading.Thread(
            target=self._heartbeat_loop,
            name="docvault-lock-heartbeat",
            daemon=True,
        )
        self._thread.start()

    def release(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=HEARTBEAT_SECONDS + 1)
            self._thread = None
        if self._record is None:
            return
        current = read_lock(self._paths.lock)
        if current is not None and current.instance_id == self._record.instance_id:
            with contextlib.suppress(OSError):
                self._paths.lock.unlink()
        self._record = None

    def __enter__(self) -> VaultLock:
        return self.acquire()

    def __exit__(self, *_exc: object) -> None:
        self.release()
