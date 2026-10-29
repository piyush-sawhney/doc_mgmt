"""The ``docvault`` command boundary, exercised end to end.

Provisioning and dump internals already have integration coverage. These tests
drive ``main`` itself: argument parsing, config loading, the passphrase prompt,
exit codes, and the rule that a failed ``init`` leaves nothing behind
(``docs/09`` §1).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app import cli
from app.core.errors import DocVaultError

from .conftest import Pair

PASSPHRASE = "Stapler-Harbor-Cactus-42"

CONFIG = """\
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

[office]
convert_exe = ""
"""


@pytest.fixture
def configured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A config with an empty vault root and an in-process passphrase prompt."""
    path = tmp_path / "docvault.toml"
    path.write_text(CONFIG, encoding="utf-8")
    monkeypatch.setattr(cli, "_prompt_passphrase", lambda **_: PASSPHRASE)
    return path


def test_init_without_a_database_creates_a_vault_and_records_its_root(
    configured: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "vault"

    code = cli.main(
        ["init", "--config", str(configured), "--vault", str(root), "--no-database", "--no-tls"]
    )

    assert code == cli.EXIT_OK
    assert (root / "manifest.json").is_file()
    assert (root / "keys" / "kek.wrapped").is_file()
    assert "vault_id:" in capsys.readouterr().out
    assert f'root = "{root}"' in configured.read_text(encoding="utf-8")


def test_a_second_init_is_refused_and_does_not_touch_the_existing_vault(
    configured: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "vault"
    arguments = [
        "init",
        "--config",
        str(configured),
        "--vault",
        str(root),
        "--no-database",
        "--no-tls",
    ]
    assert cli.main(arguments) == cli.EXIT_OK
    manifest = (root / "manifest.json").read_bytes()
    key = (root / "keys" / "kek.wrapped").read_bytes()
    capsys.readouterr()

    code = cli.main(arguments)

    assert code == cli.EXIT_ERROR
    assert "VAULT_ALREADY_EXISTS" in capsys.readouterr().err
    assert (root / "manifest.json").read_bytes() == manifest
    assert (root / "keys" / "kek.wrapped").read_bytes() == key


def test_reuse_vault_without_an_existing_vault_is_refused(
    configured: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "vault"

    code = cli.main(
        [
            "init",
            "--config",
            str(configured),
            "--vault",
            str(root),
            "--reuse-vault",
            "--no-database",
        ]
    )

    assert code == cli.EXIT_ERROR
    assert "VAULT_NOT_FOUND" in capsys.readouterr().err
    assert not (root / "manifest.json").exists()


def test_a_weak_passphrase_fails_before_anything_is_written(
    configured: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "vault"
    monkeypatch.setattr(cli, "_prompt_passphrase", lambda **_: "password")

    code = cli.main(
        ["init", "--config", str(configured), "--vault", str(root), "--no-database", "--no-tls"]
    )

    assert code == cli.EXIT_ERROR
    assert "PASSPHRASE" in capsys.readouterr().err
    assert not (root / "manifest.json").exists()


def test_a_mismatched_passphrase_is_refused(
    configured: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "vault"

    def prompt(*, confirm: bool) -> str:
        del confirm
        raise DocVaultError("PASSPHRASE_MISMATCH")

    monkeypatch.setattr(cli, "_prompt_passphrase", prompt)

    assert (
        cli.main(
            ["init", "--config", str(configured), "--vault", str(root), "--no-database", "--no-tls"]
        )
        == cli.EXIT_ERROR
    )
    assert not (root / "manifest.json").exists()


def test_init_migrate_backup_and_dump_list_end_to_end(
    pair: Pair,
    pg_admin_dsn: str,
    configured: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configured.write_text(
        CONFIG.replace(
            'dsn = "postgresql://docvault_app@127.0.0.1:5433/docvault"',
            f'dsn = "{pair.libpq_dsn}"',
        ),
        encoding="utf-8",
    )
    root = tmp_path / "vault"
    common = ["--config", str(configured)]

    init = cli.main(
        [
            "init",
            *common,
            "--vault",
            str(root),
            "--admin-dsn",
            pg_admin_dsn,
            "--no-tls",
        ]
    )
    assert init == cli.EXIT_OK
    assert (root / "manifest.json").is_file()
    assert (root / "index" / "db" / "LATEST").is_file()
    credential = configured.parent / "docvault-db.cred"
    assert credential.is_file()
    assert credential.stat().st_mode & 0o777 == 0o600

    assert cli.main(["migrate", *common]) == cli.EXIT_OK
    assert cli.main(["backup", *common]) == cli.EXIT_OK
    assert cli.main(["dump-list", *common]) == cli.EXIT_OK
    output = capsys.readouterr().out
    assert "docvault" in output.lower() or "database" in output.lower()
