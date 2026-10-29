"""Private local IPC for locking and unlocking a running vault service."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import stat
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.core.errors import DocVaultError
from app.vault.session import VaultManager

MAX_MESSAGE_BYTES = 4096
LOGGER = logging.getLogger(__name__)


def control_socket_path(root: Path) -> Path:
    if os.name != "posix" or not hasattr(os, "getuid"):
        raise DocVaultError(
            "NOT_READY", detail="Live vault lock IPC is currently available on POSIX systems."
        )
    directory = Path(tempfile.gettempdir()) / f"docvault-{os.getuid()}"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise DocVaultError("NOT_READY", detail="The private control-socket directory is unsafe.")
    digest = hashlib.sha256(str(root.expanduser().resolve()).encode("utf-8")).hexdigest()[:32]
    return directory / f"{digest}.sock"


def send_control_command(
    root: Path, command: str, *, passphrase: str | None = None
) -> dict[str, Any]:
    path = control_socket_path(root)
    request: dict[str, str] = {"command": command}
    if passphrase is not None:
        request["passphrase"] = passphrase
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(10)
            client.connect(str(path))
            client.sendall(json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n")
            response = bytearray()
            while len(response) <= MAX_MESSAGE_BYTES:
                chunk = client.recv(min(1024, MAX_MESSAGE_BYTES + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                if b"\n" in chunk:
                    break
    except OSError as exc:
        raise DocVaultError(
            "NOT_READY", detail="The vault service control socket is unavailable."
        ) from exc
    if len(response) > MAX_MESSAGE_BYTES or not response:
        raise DocVaultError("BAD_REQUEST", detail="The vault service returned an invalid response.")
    try:
        payload = json.loads(response.split(b"\n", 1)[0])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DocVaultError(
            "BAD_REQUEST", detail="The vault service returned invalid JSON."
        ) from exc
    if not isinstance(payload, dict) or not payload.get("ok"):
        code = payload.get("code") if isinstance(payload, dict) else None
        detail = payload.get("detail") if isinstance(payload, dict) else None
        raise DocVaultError(
            str(code or "BAD_REQUEST"), detail=str(detail or "Control request failed.")
        )
    return payload


class VaultControlServer:
    def __init__(
        self,
        manager: VaultManager,
        *,
        on_lock: Callable[[], int] | None = None,
    ) -> None:
        self._manager = manager
        self._on_lock = on_lock
        self._path = control_socket_path(manager.paths.root)
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._socket_identity: tuple[int, int] | None = None

    def start(self) -> VaultControlServer:
        if self._path.exists():
            info = self._path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                raise DocVaultError(
                    "VAULT_LOCKED_BY_OTHER", detail="The control socket path is unsafe."
                )
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(2)
                try:
                    probe.connect(str(self._path))
                except (ConnectionRefusedError, FileNotFoundError):
                    self._path.unlink()
                except OSError as exc:
                    raise DocVaultError(
                        "NOT_READY", detail="The existing control socket cannot be checked."
                    ) from exc
                else:
                    raise DocVaultError(
                        "VAULT_LOCKED_BY_OTHER", detail="The service is already running."
                    )
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self._path))
            self._path.chmod(0o600)
            listener.listen(5)
            listener.settimeout(0.5)
        except OSError as exc:
            listener.close()
            raise DocVaultError(
                "NOT_READY", detail="The control socket could not be started."
            ) from exc
        info = self._path.stat()
        self._socket_identity = (info.st_dev, info.st_ino)
        self._listener = listener
        self._thread = threading.Thread(
            target=self._serve,
            name="docvault-control",
            daemon=True,
        )
        self._thread.start()
        return self

    def _respond(self, client: socket.socket) -> None:
        request = bytearray()
        while len(request) <= MAX_MESSAGE_BYTES:
            chunk = client.recv(min(1024, MAX_MESSAGE_BYTES + 1 - len(request)))
            if not chunk or b"\n" in chunk:
                request.extend(chunk.split(b"\n", 1)[0] if chunk else b"")
                break
            request.extend(chunk)
        if len(request) > MAX_MESSAGE_BYTES:
            payload: dict[str, Any] = {
                "ok": False,
                "code": "BAD_REQUEST",
                "detail": "Request too large.",
            }
        else:
            try:
                command = json.loads(request)
                if not isinstance(command, dict):
                    raise ValueError("The control request must be an object.")
                action = command.get("command")
                if action == "lock":
                    revoked_sessions = self._on_lock() if self._on_lock is not None else 0
                    self._manager.lock()
                    payload = {
                        "ok": True,
                        "locked": True,
                        "revoked_sessions": revoked_sessions,
                    }
                elif action == "unlock" and isinstance(command.get("passphrase"), str):
                    identity = self._manager.unlock(command["passphrase"])
                    payload = {
                        "ok": True,
                        "locked": False,
                        "vault_id": identity.vault_id,
                        "key_fingerprint": identity.key_fingerprint,
                    }
                elif action == "status":
                    payload = {"ok": True, "locked": self._manager.locked}
                else:
                    payload = {
                        "ok": False,
                        "code": "BAD_REQUEST",
                        "detail": "Unknown control action.",
                    }
            except DocVaultError as exc:
                payload = {"ok": False, "code": exc.code, "detail": exc.detail}
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                payload = {"ok": False, "code": "BAD_REQUEST", "detail": "Invalid control request."}
        client.sendall(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")

    def _serve(self) -> None:
        while not self._stop.is_set():
            listener = self._listener
            if listener is None:
                break
            try:
                client, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self._stop.is_set():
                    raise
                break
            with client:
                client.settimeout(10)
                try:
                    self._respond(client)
                except (OSError, TimeoutError):
                    LOGGER.warning("local control client disconnected before response")

    def close(self) -> None:
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        try:
            info = self._path.stat()
        except FileNotFoundError:
            return
        if self._socket_identity == (info.st_dev, info.st_ino):
            self._path.unlink(missing_ok=True)

    def __enter__(self) -> VaultControlServer:
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.close()
