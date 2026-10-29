from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from app.core.errors import DocVaultError
from app.vault.control import VaultControlServer, control_socket_path, send_control_command
from app.vault.session import VaultManager


@pytest.mark.skipif(os.name != "posix", reason="The current control transport uses POSIX sockets.")
def test_running_service_can_be_locked_and_unlocked_over_private_ipc(
    vault: tuple[Path, str, object],
) -> None:
    root, passphrase, _result = vault
    manager = VaultManager(root, app_version="test")
    manager.open()
    manager.unlock(passphrase)
    server = VaultControlServer(manager, on_lock=lambda: 3)

    try:
        with server:
            socket_path = control_socket_path(root)
            assert stat.S_IMODE(socket_path.stat().st_mode) == 0o600

            locked = send_control_command(root, "lock")
            assert locked["locked"] is True
            assert locked["revoked_sessions"] == 3
            assert manager.locked is True
            with pytest.raises(DocVaultError) as caught:
                _ = manager.keys
            assert caught.value.code == "VAULT_LOCKED"

            with pytest.raises(DocVaultError) as bad_passphrase:
                send_control_command(root, "unlock", passphrase="wrong")
            assert bad_passphrase.value.code == "BAD_PASSPHRASE"
            assert manager.locked is True
            unlocked = send_control_command(root, "unlock", passphrase=passphrase)
            assert unlocked["locked"] is False
            assert manager.locked is False
            assert manager.keys.fingerprint == unlocked["key_fingerprint"]
    finally:
        server.close()
        manager.close()
