"""Shared fixtures. Temporary directories only; no test touches a real vault."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import DatabaseSettings, Settings, VaultSettings
from app.crypto.keys import VaultKeys, derive_keys
from app.vault.init import InitResult, create_vault

STRONG_PASSPHRASE = "Stapler-Harbor-Cactus-42"


@pytest.fixture
def keys() -> VaultKeys:
    return derive_keys(bytes(range(32)))


@pytest.fixture
def vault(tmp_path: Path) -> tuple[Path, str, InitResult]:
    root = tmp_path / "vault"
    result = create_vault(
        root,
        passphrase=STRONG_PASSPHRASE,
        display_name="Test vault",
        max_file_bytes=10 * 1024 * 1024,
        app_version="0.1.0-test",
    )
    return root, STRONG_PASSPHRASE, result


@pytest.fixture
def settings(tmp_path: Path, vault: tuple[Path, str, InitResult]) -> Settings:
    root, _passphrase, _result = vault
    return Settings(
        environment="development",
        vault=VaultSettings(root=root),
        database=DatabaseSettings(
            dsn="postgresql://docvault_app@127.0.0.1:5433/docvault",
            pg_bin_dir=Path("/usr/lib/postgresql/18/bin"),
        ),
    )
