"""Filesystem probes and atomic writes."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from app.core.errors import DocVaultError
from app.vault import layout
from app.vault.layout import (
    VaultPaths,
    atomic_write,
    ensure_layout,
    probe_root,
    vault_paths,
)


def test_probe_creates_the_layout(tmp_path: Path) -> None:
    # Act
    report = probe_root(tmp_path / "vault")

    # Assert
    paths = vault_paths(tmp_path / "vault")
    assert report.filesystem != ""
    assert paths.manifest.parent.is_dir()
    assert paths.blobs.is_dir()
    assert paths.dump_dir.is_dir()
    assert paths.audit_dir.is_dir()
    assert paths.tmp.is_dir()
    assert paths.trash.is_dir()


def test_atomic_write_leaves_exact_content(tmp_path: Path) -> None:
    # Arrange
    target = tmp_path / "keys" / "kek.wrapped"

    # Act
    atomic_write(target, b"exactly ninety-six bytes")

    # Assert
    assert target.read_bytes() == b"exactly ninety-six bytes"
    assert not list(target.parent.glob("*.part"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_directories_and_files_are_private(tmp_path: Path) -> None:
    # Arrange
    paths = vault_paths(tmp_path / "vault")
    probe_root(paths.root)

    # Act
    atomic_write(paths.kek, b"x" * 96)

    # Assert
    assert stat.S_IMODE(paths.root.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths.kek.stat().st_mode) == 0o600


def test_symlink_root_is_rejected(tmp_path: Path) -> None:
    # Arrange
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)

    # Act / Assert
    with pytest.raises(DocVaultError) as caught:
        probe_root(link)
    assert caught.value.code == "FS_SYMLINK"


def test_network_filesystem_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    monkeypatch.setattr(layout, "filesystem_type", lambda _path: "nfs")

    # Act / Assert
    with pytest.raises(DocVaultError) as caught:
        probe_root(tmp_path / "vault")
    assert caught.value.code == "FS_NETWORK_PATH"


def test_relative_root_is_rejected() -> None:
    # Act / Assert
    with pytest.raises(DocVaultError):
        vault_paths(Path("relative/vault"))


def test_blob_path_is_fanout_and_rejects_bad_addresses(tmp_path: Path) -> None:
    # Arrange
    paths: VaultPaths = vault_paths(tmp_path / "vault")
    address = "9f" + "3a" + "c1" * 30

    # Act
    path = paths.blob(address)

    # Assert
    assert path.parent.name == "3a"
    assert path.parent.parent.name == "9f"
    with pytest.raises(DocVaultError):
        paths.blob("../escape")


def test_ensure_layout_is_idempotent(tmp_path: Path) -> None:
    # Arrange
    paths = vault_paths(tmp_path / "vault")

    # Act
    ensure_layout(paths)
    ensure_layout(paths)

    # Assert
    assert paths.blobs.is_dir()
