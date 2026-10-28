"""The database credential file.

Development stores it in a ``0600`` file beside the configuration. The format is
small, so the tests are too: one round trip, one refusal, and the ways a damaged
file is reported.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import pytest

from app.core.errors import DocVaultError
from app.db.credentials import (
    CREDENTIAL_NAME,
    Credential,
    credential_path,
    load_credential,
    save_credential,
)


@pytest.fixture
def config(tmp_path: Path) -> Path:
    path = tmp_path / "docvault.toml"
    path.write_text('environment = "development"\n', encoding="utf-8")
    return path


def test_credential_lives_beside_the_configuration(config: Path) -> None:
    path = credential_path(config)
    assert path == config.parent / CREDENTIAL_NAME
    assert not path.exists()


def test_round_trip_writes_a_private_file(config: Path) -> None:
    credential = Credential(role="docvault_app", password=secrets.token_urlsafe(24))
    path = credential_path(config)

    save_credential(path, credential, environment="development")

    assert load_credential(path) == credential
    assert path.stat().st_mode & 0o777 == 0o600


def test_a_missing_file_names_the_remedy(config: Path) -> None:
    with pytest.raises(DocVaultError) as excinfo:
        load_credential(credential_path(config))
    assert excinfo.value.code == "DB_CREDENTIAL_UNREADABLE"
    assert "init" in excinfo.value.remediation


@pytest.mark.parametrize(
    "payload",
    [
        b"not json at all",
        b'{"format": 1}',
        b'{"format": 99, "role": "docvault_app", "password": "x"}',
        b'{"format": 1, "role": 1, "password": "x"}',
    ],
)
def test_a_damaged_file_is_unreadable(config: Path, payload: bytes) -> None:
    path = credential_path(config)
    path.write_bytes(payload)
    with pytest.raises(DocVaultError) as excinfo:
        load_credential(path)
    assert excinfo.value.code == "DB_CREDENTIAL_UNREADABLE"


def test_production_refuses_the_file_fallback(config: Path) -> None:
    if os.name == "nt":  # pragma: no cover - DPAPI is the production path there
        pytest.skip("Windows uses DPAPI, so the fallback is not reachable.")
    path = credential_path(config)
    credential = Credential(role="docvault_app", password=secrets.token_urlsafe(24))
    with pytest.raises(DocVaultError) as excinfo:
        save_credential(path, credential, environment="production")
    assert excinfo.value.code == "DB_CREDENTIAL_UNREADABLE"
    assert not path.exists()
