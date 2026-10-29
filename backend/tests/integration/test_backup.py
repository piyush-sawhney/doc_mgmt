"""Dumps and restores against real PostgreSQL 18.

The dump is produced by the real ``pg_dump``, encrypted by the real container,
and restored by the real ``pg_restore`` into a second database. Nothing here is
mocked: the failure modes that matter are subprocess and SQL ones.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.core.errors import DocVaultError
from app.db import backup, bootstrap, connect, migrate
from app.db.credentials import Credential
from app.vault.layout import vault_paths

from .conftest import Pair

VAULT_ID = "0192f0c4-7a1e-7c3b-9a55-2c1f0b6d4e11"
STRANGER_ID = "0192f0c4-0000-7000-8000-000000000000"


@pytest.fixture
def context(pair: Pair, keys, tmp_path: Path) -> backup.BackupContext:
    """A migrated, seeded database and an empty vault layout to dump into."""
    migrate.upgrade(pair.dsn)
    engine = create_engine(pair.dsn)
    try:
        with engine.connect() as connection:
            bootstrap.bootstrap_database(
                connection,
                meta_key=keys.meta_key,
                vault_id=VAULT_ID,
            )
        info = connect.server_info(engine)
    finally:
        engine.dispose()
    paths = vault_paths((tmp_path / "vault").resolve())
    paths.dump_dir.mkdir(parents=True)
    paths.tmp.mkdir(parents=True)
    return backup.BackupContext(
        paths=paths,
        dsn=pair.libpq_dsn,
        credential=Credential(role=pair.role, password=pair.password),
        pg_bin_dir=Path("/usr/lib/postgresql/18/bin"),
        dump_key=keys.dump_key,
        vault_id=VAULT_ID,
        schema_version=1,
        server_version=info.version,
        keep=7,
    )


@pytest.fixture
def empty_database(pg_admin_dsn: str, pair: Pair) -> Iterator[str]:
    """A second empty database, owned by the same app role, dropped afterwards."""
    name = f"{pair.database}_restore"
    admin = create_engine(pg_admin_dsn, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{name}" OWNER "{pair.role}"'))
        yield name
    finally:
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _dsn_for(pair: Pair, database: str) -> str:
    return make_url(pair.libpq_dsn).set(database=database).render_as_string(hide_password=False)


def test_a_dump_is_encrypted_and_latest_points_at_it(context: backup.BackupContext) -> None:
    pointer = backup.create_backup(context)

    assert pointer.file.startswith("docvault-")
    assert pointer.file.endswith(".dump.enc")
    assert pointer.vault_id == VAULT_ID
    assert pointer.pg_version.startswith("18.")
    path = context.paths.dump_dir / pointer.file
    assert path.read_bytes()[:4] == b"DVD1"
    assert b"CREATE TABLE" not in path.read_bytes()
    assert backup.read_latest(context.paths) == pointer
    assert backup.dumps(context.paths) == [path]


def test_a_dump_restores_into_an_empty_database(
    context: backup.BackupContext,
    pair: Pair,
    keys,
    empty_database: str,
) -> None:
    backup.create_backup(context)
    target = replace(context, dsn=_dsn_for(pair, empty_database))

    result = backup.restore_dump(target)

    assert result.from_latest is True
    assert result.plaintext_bytes > 0
    engine = create_engine(_dsn_for(pair, empty_database))
    try:
        with engine.connect() as connection:
            types = connection.execute(text("SELECT count(*) FROM doc_types")).scalar_one()
            settings = connection.execute(text("SELECT count(*) FROM settings")).scalar_one()
            assert types == 81
            assert settings == 2
            identity = bootstrap.check_bootstrap(
                connection,
                meta_key=keys.meta_key,
                vault_id=VAULT_ID,
            )
            assert identity.schema_version == 1
    finally:
        engine.dispose()


def test_dump_list_reads_the_toc_without_restoring(context: backup.BackupContext) -> None:
    backup.create_backup(context)
    listing = backup.list_dump(context)
    assert "doc_types" in listing
    assert "TABLE" in listing


def test_latest_from_another_vault_is_refused_before_the_database(
    context: backup.BackupContext,
    pair: Pair,
    empty_database: str,
) -> None:
    backup.create_backup(context)
    target = replace(
        context,
        dsn=_dsn_for(pair, empty_database),
        vault_id=STRANGER_ID,
    )
    with pytest.raises(DocVaultError) as excinfo:
        backup.restore_dump(target)
    assert excinfo.value.code == "DUMP_MISMATCH"

    engine = create_engine(_dsn_for(pair, empty_database))
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT to_regclass('public.doc_types')")).scalar_one()
                is None
            )
    finally:
        engine.dispose()


def test_a_corrupted_dump_is_refused(context: backup.BackupContext) -> None:
    pointer = backup.create_backup(context)
    path = context.paths.dump_dir / pointer.file
    path.write_bytes(path.read_bytes() + b"x")
    with pytest.raises(DocVaultError) as excinfo:
        backup.restore_dump(context)
    assert excinfo.value.code == "DUMP_MISMATCH"


def test_a_tampered_dump_with_a_consistent_pointer_fails_authentication(
    context: backup.BackupContext,
) -> None:
    pointer = backup.create_backup(context)
    path = context.paths.dump_dir / pointer.file
    data = bytearray(path.read_bytes())
    data[-1] ^= 0x01
    path.write_bytes(data)
    tampered = replace(pointer, size=len(data), sha256=backup.dump.file_sha256(path))
    backup.write_latest(context.paths, tampered)

    with pytest.raises(DocVaultError) as excinfo:
        backup.restore_dump(context)
    assert excinfo.value.code == "DUMP_TAMPERED"


def test_a_missing_dump_is_named(context: backup.BackupContext) -> None:
    backup.create_backup(context)
    for path in context.paths.dump_dir.glob("*.dump.enc"):
        path.unlink()
    with pytest.raises(DocVaultError) as excinfo:
        backup.restore_dump(context)
    assert excinfo.value.code == "DUMP_NOT_FOUND"


def test_rotation_keeps_the_last_n_and_every_pre_migration_dump(
    context: backup.BackupContext,
) -> None:
    base = datetime(2026, 10, 28, 1, 0, tzinfo=UTC)
    pre = backup.create_backup(context, pre_migration=True, moment=base)
    first = backup.create_backup(context, moment=base + timedelta(minutes=1))
    narrow = replace(context, keep=1)
    newest = backup.create_backup(narrow, moment=base + timedelta(minutes=2))

    names = {path.name for path in backup.dumps(context.paths)}
    assert names == {pre.file, newest.file}
    assert first.file not in names
    assert pre.pre_migration is True


def test_a_failed_client_leaves_latest_untouched(context: backup.BackupContext) -> None:
    pointer = backup.create_backup(context)
    later = datetime.now(UTC) + timedelta(minutes=5)
    broken = replace(context, pg_bin_dir=Path("/nonexistent/postgresql/bin"))
    with pytest.raises(DocVaultError) as excinfo:
        backup.create_backup(broken, moment=later)
    assert excinfo.value.code == "PG_CLIENT_MISSING"
    assert backup.read_latest(context.paths) == pointer


def test_bad_dump_names_are_refused(context: backup.BackupContext) -> None:
    pointer = backup.create_backup(context)
    with pytest.raises(DocVaultError) as excinfo:
        backup.dump_path(context.paths, f"../{pointer.file}")
    assert excinfo.value.code == "DUMP_INVALID"
    with pytest.raises(DocVaultError) as missing:
        backup.restore_dump(context, name="docvault-20260101T000000Z.dump.enc")
    assert missing.value.code == "DUMP_NOT_FOUND"
