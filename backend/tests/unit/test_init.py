"""Vault creation, identity, and the session unlock path."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.errors import DocVaultError
from app.core.time import now_utc
from app.vault import audit
from app.vault.init import create_vault, read_identity
from app.vault.layout import atomic_write, vault_paths
from app.vault.session import VaultManager


def test_create_vault_writes_identity_and_key(vault: tuple[Path, str, object]) -> None:
    # Arrange
    root, _passphrase, result = vault

    # Act
    paths = vault_paths(root)
    identity = read_identity(root)

    # Assert
    assert paths.manifest.is_file()
    assert paths.kek.is_file()
    assert paths.kek.stat().st_size == 96
    assert identity.vault_id == result.vault_id
    assert identity.key_fingerprint == result.key_fingerprint
    assert len(result.key_fingerprint) == 32


def test_second_init_refuses_to_overwrite(vault: tuple[Path, str, object]) -> None:
    # Arrange
    root, passphrase, _result = vault

    # Act / Assert
    with pytest.raises(DocVaultError) as caught:
        create_vault(
            root,
            passphrase=passphrase,
            display_name="Again",
            max_file_bytes=1024,
            app_version="test",
        )
    assert caught.value.code == "VAULT_ALREADY_EXISTS"


def test_weak_passphrase_is_refused(tmp_path: Path) -> None:
    # Act / Assert
    with pytest.raises(DocVaultError) as caught:
        create_vault(
            tmp_path / "vault",
            passphrase="passwordpassword",
            display_name="Weak",
            max_file_bytes=1024,
            app_version="test",
        )
    assert caught.value.code == "PASSPHRASE_POLICY"


def test_a_write_failure_leaves_no_half_initialised_vault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "vault"
    calls = 0

    def failing_write(path: Path, data: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("disk full")
        atomic_write(path, data)

    monkeypatch.setattr("app.vault.init.atomic_write", failing_write)

    with pytest.raises(OSError, match="disk full"):
        create_vault(
            root,
            passphrase="Stapler-Harbor-Cactus-42",
            display_name="Half",
            max_file_bytes=1024,
            app_version="test",
        )

    paths = vault_paths(root)
    assert not paths.manifest.exists()
    assert not paths.kek.exists()
    assert audit.verify_chain(paths.audit_dir).entries == 0
    assert not (tmp_path / "vault" / "manifest.json").exists()


def test_unlock_derives_the_manifest_key(vault: tuple[Path, str, object]) -> None:
    # Arrange
    root, passphrase, _result = vault
    manager = VaultManager(root, app_version="test")

    # Act
    manager.open()
    identity = manager.unlock(passphrase)

    # Assert
    assert identity.vault_id == _result.vault_id
    assert manager.locked is False
    assert manager.keys.fingerprint == identity.key_fingerprint
    manager.close()


def test_wrong_passphrase_is_audited_and_stays_locked(vault: tuple[Path, str, object]) -> None:
    # Arrange
    root, _passphrase, _result = vault
    manager = VaultManager(root, app_version="test")
    manager.open()

    # Act / Assert
    with pytest.raises(DocVaultError):
        manager.unlock("Wrong-Harbor-Cactus-42")
    assert manager.locked is True
    manager.close()

    check = audit.verify_chain(vault_paths(root).audit_dir)
    assert check.ok is True
    text = (vault_paths(root).audit_dir / audit.month_for(now_utc())).read_text(encoding="utf-8")
    assert "vault.unlock.deny" in text


def test_status_does_not_require_unlocking(vault: tuple[Path, str, object]) -> None:
    # Arrange
    root, _passphrase, result = vault
    manager = VaultManager(root, app_version="test")

    # Act
    manager.open()
    status = manager.status()

    # Assert
    assert status.vault_id == result.vault_id
    assert status.locked is True
    assert status.lock.held is True
    manager.close()


def test_close_releases_the_lock(vault: tuple[Path, str, object]) -> None:
    # Arrange
    root, _passphrase, _result = vault
    manager = VaultManager(root, app_version="test")
    manager.open()

    # Act
    manager.close()

    # Assert
    assert vault_paths(root).lock.exists() is False
