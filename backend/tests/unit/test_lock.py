"""Single-writer lock acquisition, staleness, and forced takeover."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from app.core.errors import DocVaultError
from app.core.time import format_seconds, now_utc
from app.vault import audit
from app.vault.layout import probe_root, vault_paths
from app.vault.lock import VaultLock, lock_status, read_lock


def _paths(tmp_path: Path):
    root = tmp_path / "vault"
    probe_root(root)
    return vault_paths(root)


def test_second_writer_is_refused(tmp_path: Path) -> None:
    # Arrange
    paths = _paths(tmp_path)
    first = VaultLock(paths, vault_id="vault-1", app_version="test").acquire()

    # Act / Assert
    try:
        with pytest.raises(DocVaultError) as caught:
            VaultLock(paths, vault_id="vault-1", app_version="test").acquire()
        assert caught.value.code == "VAULT_LOCKED_BY_OTHER"
    finally:
        first.release()


def test_release_removes_the_lock(tmp_path: Path) -> None:
    # Arrange
    paths = _paths(tmp_path)
    lock = VaultLock(paths, vault_id="vault-1", app_version="test")

    # Act
    lock.acquire()
    held = paths.lock.is_file()
    lock.release()

    # Assert
    assert held is True
    assert paths.lock.exists() is False


def test_heartbeat_record_is_readable(tmp_path: Path) -> None:
    # Arrange
    paths = _paths(tmp_path)

    # Act
    with VaultLock(paths, vault_id="vault-1", app_version="test"):
        record = read_lock(paths.lock)

    # Assert
    assert record is not None
    assert record.vault_id == "vault-1"
    assert record.app_version == "test"


def test_stale_lock_can_be_taken_over_only_with_force(tmp_path: Path) -> None:
    # Arrange
    paths = _paths(tmp_path)
    old = format_seconds(now_utc() - timedelta(minutes=5))
    paths.lock.write_text(
        json.dumps(
            {
                "instance_id": "old",
                "vault_id": "vault-1",
                "host_id": "sha256:old",
                "pid": 1,
                "app_version": "0.9.0",
                "started_at": old,
                "heartbeat_at": old,
            }
        ),
        encoding="utf-8",
    )

    # Act / Assert
    assert lock_status(paths.lock).stale is True
    with pytest.raises(DocVaultError):
        VaultLock(paths, vault_id="vault-1", app_version="test").acquire()

    lock = VaultLock(paths, vault_id="vault-1", app_version="test", force=True).acquire()
    try:
        assert lock.record is not None
        assert lock.record.instance_id != "old"
    finally:
        lock.release()


def test_forced_takeover_is_audited(tmp_path: Path) -> None:
    # Arrange
    paths = _paths(tmp_path)
    old = format_seconds(now_utc() - timedelta(minutes=5))
    paths.lock.write_text(
        json.dumps(
            {
                "instance_id": "old",
                "vault_id": "vault-1",
                "host_id": "sha256:old",
                "pid": 1,
                "app_version": "0.9.0",
                "started_at": old,
                "heartbeat_at": old,
            }
        ),
        encoding="utf-8",
    )

    # Act
    lock = VaultLock(paths, vault_id="vault-1", app_version="test", force=True).acquire()
    lock.release()

    # Assert
    text = (paths.audit_dir / audit.month_for(now_utc())).read_text(encoding="utf-8")
    assert "vault.lock.forced" in text
