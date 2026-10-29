"""The ``LATEST`` pointer, dump names, and rotation.

These do not need PostgreSQL: they are the filesystem contract around a dump.
The subprocess path is covered by the integration suite.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.core.errors import DocVaultError
from app.db import backup
from app.vault.layout import vault_paths

SHA = "0b6f" + "0" * 60
VAULT_ID = "0192f0c4-7a1e-7c3b-9a55-2c1f0b6d4e11"


def _pointer(name: str = "docvault-20261028T010000Z.dump.enc") -> backup.DumpPointer:
    return backup.DumpPointer(
        file=name,
        size=48_213_904,
        plaintext_bytes=120_435_712,
        sha256=SHA,
        created_at="2026-10-28T01:00:00Z",
        pg_version="18.6",
        schema_version=1,
        vault_id=VAULT_ID,
    )


def test_pointer_round_trips_in_the_documented_order() -> None:
    pointer = _pointer()
    text = pointer.serialise()
    assert text.splitlines()[0] == f"file={pointer.file}"
    assert text.splitlines()[-1] == f"vault_id={VAULT_ID}"
    assert backup.DumpPointer.parse(text) == pointer


def test_pointer_marks_a_pre_migration_dump() -> None:
    pointer = _pointer("docvault-20261028T010000Z-pre-migration.dump.enc")
    assert pointer.pre_migration is True
    text = pointer.serialise()
    assert "pre-migration" in backup.DumpPointer.parse(text).file


@pytest.mark.parametrize(
    "text",
    [
        "",
        "file=docvault-20261028T010000Z.dump.enc\n",
        _pointer()
        .serialise()
        .replace(
            "file=docvault-20261028T010000Z.dump.enc",
            "file=../escape.dump.enc",
        ),
        _pointer().serialise().replace("format=DVD1", "format=ZIP"),
        _pointer().serialise().replace("encrypted=1", "encrypted=0"),
        _pointer().serialise().replace(f"sha256={SHA}", "sha256=nope"),
        _pointer().serialise().replace("size=48213904", "size=-1"),
    ],
)
def test_a_bad_pointer_is_refused(text: str) -> None:
    with pytest.raises(DocVaultError) as excinfo:
        backup.DumpPointer.parse(text)
    assert excinfo.value.code == "DUMP_INVALID"


def test_a_dump_name_cannot_escape_the_folder(tmp_path: Path) -> None:
    paths = vault_paths(tmp_path.resolve())
    with pytest.raises(DocVaultError) as excinfo:
        backup.dump_path(paths, "../docvault-20261028T010000Z.dump.enc")
    assert excinfo.value.code == "DUMP_INVALID"


def test_names_are_utc_and_sortable() -> None:
    moment = datetime(2026, 10, 28, 1, 0, 0, tzinfo=UTC)
    assert backup.dump_filename(moment) == "docvault-20261028T010000Z.dump.enc"
    assert (
        backup.dump_filename(moment, pre_migration=True)
        == "docvault-20261028T010000Z-pre-migration.dump.enc"
    )


def test_rotation_keeps_the_newest_and_every_pre_migration_dump(tmp_path: Path) -> None:
    paths = vault_paths(tmp_path.resolve())
    paths.dump_dir.mkdir(parents=True)
    for hour in range(1, 6):
        (paths.dump_dir / f"docvault-20261028T0{hour}0000Z.dump.enc").write_bytes(b"x")
    pre = paths.dump_dir / "docvault-20260901T000000Z-pre-migration.dump.enc"
    pre.write_bytes(b"x")

    removed = backup.rotate(paths, keep=2)

    remaining = sorted(path.name for path in backup.dumps(paths))
    assert removed == [
        "docvault-20261028T010000Z.dump.enc",
        "docvault-20261028T020000Z.dump.enc",
        "docvault-20261028T030000Z.dump.enc",
    ]
    assert remaining == [
        "docvault-20260901T000000Z-pre-migration.dump.enc",
        "docvault-20261028T040000Z.dump.enc",
        "docvault-20261028T050000Z.dump.enc",
    ]


def test_server_version_is_shortened_for_latest() -> None:
    assert backup.normalise_server_version("18.6 (Ubuntu 18.6-0ubuntu0.26.04.1)") == "18.6"


def test_a_missing_latest_names_the_remedy(tmp_path: Path) -> None:
    paths = vault_paths(tmp_path.resolve())
    with pytest.raises(DocVaultError) as excinfo:
        backup.read_latest(paths)
    assert excinfo.value.code == "DUMP_NOT_FOUND"
    assert "backup" in excinfo.value.remediation
