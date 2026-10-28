"""Typed TOML configuration and the root re-write used by init."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import load_settings, write_vault_root
from app.core.errors import DocVaultError

BASE = """
environment = "development"

[server]
bind = "127.0.0.1"
port = 8443

[vault]
root = ""

[database]
dsn = "postgresql://docvault_app@127.0.0.1:5433/docvault"
pg_bin_dir = "/usr/lib/postgresql/18/bin"

[limits]
max_file_bytes = 52428800

[render]
cache_bytes = 1073741824

[office]
convert_exe = ""

[log]
level = "debug"
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "docvault.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_the_development_shape(tmp_path: Path) -> None:
    # Arrange
    path = _write(tmp_path, BASE)

    # Act
    loaded = load_settings(path)

    # Assert
    assert loaded.settings.environment == "development"
    assert loaded.settings.vault.root is None
    assert loaded.settings.server.port == 8443
    assert loaded.settings.database.dsn.endswith("/docvault")


def test_unknown_key_is_a_config_error(tmp_path: Path) -> None:
    # Arrange
    path = _write(tmp_path, BASE + '\n[vault]\nroots = "/tmp/typo"\n')

    # Act / Assert
    with pytest.raises(DocVaultError) as caught:
        load_settings(path)
    assert caught.value.code == "CONFIG_INVALID"


def test_remote_database_is_refused(tmp_path: Path) -> None:
    # Arrange
    path = _write(
        tmp_path,
        BASE.replace("127.0.0.1:5433", "192.168.1.5:5432"),
    )

    # Act / Assert
    with pytest.raises(DocVaultError) as caught:
        load_settings(path)
    assert caught.value.code == "CONFIG_INVALID"


def test_relative_vault_root_is_refused(tmp_path: Path) -> None:
    # Arrange
    path = _write(tmp_path, BASE.replace('root = ""', 'root = "var/vault"'))

    # Act / Assert
    with pytest.raises(DocVaultError):
        load_settings(path)


def test_missing_file_is_named(tmp_path: Path) -> None:
    with pytest.raises(DocVaultError) as caught:
        load_settings(tmp_path / "absent.toml")
    assert caught.value.code == "CONFIG_MISSING"


def test_write_vault_root_preserves_comments(tmp_path: Path) -> None:
    # Arrange
    text = BASE.replace('[vault]\nroot = ""', '[vault]\n# this comment must survive\nroot = ""')
    path = _write(tmp_path, text)

    # Act
    write_vault_root(path, tmp_path / "vault")

    # Assert
    text = path.read_text(encoding="utf-8")
    assert "# this comment must survive" in text
    assert f'root = "{tmp_path / "vault"}"' in text


def test_write_vault_root_adds_a_vault_section(tmp_path: Path) -> None:
    # Arrange
    path = _write(tmp_path, 'environment = "development"\n')

    # Act
    write_vault_root(path, tmp_path / "vault")

    # Assert
    text = path.read_text(encoding="utf-8")
    assert "[vault]" in text
    assert "root =" in text
