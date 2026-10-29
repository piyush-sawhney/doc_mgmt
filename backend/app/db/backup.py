"""Encrypted logical dumps: ``pg_dump`` in, ``DVD1`` out, and back.

A dump only ever exists on disk as ciphertext. ``pg_dump`` writes to a pipe, the
pipe is encrypted straight into a ``.part`` file, and the finished file is
renamed into ``index/db/`` before ``LATEST`` is replaced. A crash at any point
leaves the previous dump and pointer untouched (``docs/03`` §9).

The PostgreSQL password reaches ``pg_dump`` and ``pg_restore`` through a
transient ``PGPASSFILE`` in ``vault/tmp/``, because a subprocess cannot read
DPAPI or the keyring (``docs/08`` §2.2).
"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sqlalchemy.engine import make_url

from app.core.errors import DocVaultError
from app.core.time import format_seconds, now_utc
from app.db.credentials import Credential
from app.vault import dump
from app.vault.layout import VaultPaths, atomic_write

FILENAME = re.compile(r"^docvault-\d{8}T\d{6}Z(-pre-migration)?\.dump\.enc$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PRE_MIGRATION_SUFFIX = "-pre-migration"
CONNECT_TIMEOUT_SECONDS = 5


@dataclass(frozen=True, slots=True)
class DumpPointer:
    """The contents of ``LATEST``. Plain text, checked on restore."""

    file: str
    size: int
    plaintext_bytes: int
    sha256: str
    created_at: str
    pg_version: str
    schema_version: int
    vault_id: str
    format: str = "DVD1"
    encrypted: int = 1

    @property
    def pre_migration(self) -> bool:
        return PRE_MIGRATION_SUFFIX in self.file

    def serialise(self) -> str:
        lines = [
            f"file={self.file}",
            f"format={self.format}",
            f"encrypted={self.encrypted}",
            f"size={self.size}",
            f"plaintext_bytes={self.plaintext_bytes}",
            f"sha256={self.sha256}",
            f"created_at={self.created_at}",
            f"pg_version={self.pg_version}",
            f"schema_version={self.schema_version}",
            f"vault_id={self.vault_id}",
        ]
        return "\n".join(lines) + "\n"

    @classmethod
    def parse(cls, text: str) -> DumpPointer:
        values: dict[str, str] = {}
        for line in text.splitlines():
            if not line.strip():
                continue
            key, separator, value = line.partition("=")
            if not separator:
                raise DocVaultError("DUMP_INVALID", detail=f"Malformed LATEST line: {line!r}")
            values[key.strip()] = value.strip()
        try:
            name = values["file"]
            size = int(values["size"])
            plaintext_bytes = int(values["plaintext_bytes"])
            schema_version = int(values["schema_version"])
            pointer = cls(
                file=name,
                size=size,
                plaintext_bytes=plaintext_bytes,
                sha256=values["sha256"],
                created_at=values["created_at"],
                pg_version=values["pg_version"],
                schema_version=schema_version,
                vault_id=values["vault_id"],
                format=values.get("format", "DVD1"),
                encrypted=int(values.get("encrypted", "1")),
            )
        except (KeyError, ValueError) as exc:
            raise DocVaultError("DUMP_INVALID", detail=f"LATEST is incomplete: {exc}") from exc
        pointer.validate()
        return pointer

    def validate(self) -> None:
        if not FILENAME.match(self.file):
            raise DocVaultError("DUMP_INVALID", detail=f"Unexpected dump name {self.file!r}.")
        if self.format != "DVD1":
            raise DocVaultError("DUMP_INVALID", detail=f"Unknown dump format {self.format!r}.")
        if self.encrypted != 1:
            raise DocVaultError("DUMP_INVALID", detail="LATEST claims an unencrypted dump.")
        if self.size < dump.HEADER_SIZE + dump.TAG_SIZE or self.plaintext_bytes < 0:
            raise DocVaultError("DUMP_INVALID", detail="LATEST carries an impossible size.")
        if not SHA256.match(self.sha256):
            raise DocVaultError("DUMP_INVALID", detail="LATEST carries a malformed SHA-256.")
        if self.schema_version < 1:
            raise DocVaultError("DUMP_INVALID", detail="LATEST carries a bad schema version.")


@dataclass(frozen=True, slots=True)
class BackupContext:
    """Everything a dump needs, resolved once at the CLI boundary."""

    paths: VaultPaths
    dsn: str
    credential: Credential
    pg_bin_dir: Path
    dump_key: bytes
    vault_id: str
    schema_version: int
    server_version: str
    keep: int


@dataclass(frozen=True, slots=True)
class RestoreResult:
    """What was restored, for the operator line and the audit entry."""

    file: str
    plaintext_bytes: int
    from_latest: bool


def dump_filename(moment: datetime, *, pre_migration: bool = False) -> str:
    """``docvault-YYYYMMDDTHHMMSSZ.dump.enc``, with an optional marker."""
    utc = format_seconds(moment).replace("-", "").replace(":", "")
    suffix = f"{PRE_MIGRATION_SUFFIX}" if pre_migration else ""
    return f"docvault-{utc}{suffix}.dump.enc"


def normalise_server_version(version: str) -> str:
    """``18.6 (Ubuntu ...)`` becomes ``18.6`` for ``LATEST``."""
    return version.split(" ", 1)[0].strip()


def tool_path(pg_bin_dir: Path, name: str) -> Path:
    """Resolve ``pg_dump``/``pg_restore`` from ``pg_bin_dir`` only.

    Falling back to ``PATH`` would silently pick a distro client of another
    major, which is exactly the skew the design refuses.
    """
    executable = f"{name}.exe" if os.name == "nt" else name
    candidate = pg_bin_dir / executable
    if candidate.is_file():
        return candidate
    found = shutil.which(name, path=str(pg_bin_dir))
    if found is None:
        raise DocVaultError(
            "PG_CLIENT_MISSING",
            detail=f"{name} was not found in {pg_bin_dir}.",
            remediation="Point database.pg_bin_dir at the PostgreSQL 18 bin folder.",
        )
    return Path(found)


def _tool_version(tool: Path) -> tuple[int, ...]:
    try:
        result = subprocess.run(
            [str(tool), "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DocVaultError("PG_CLIENT_MISSING", detail=f"Cannot run {tool.name}: {exc}") from exc
    match = re.search(r"(\d+)\.(\d+)", result.stdout)
    if result.returncode != 0 or match is None:
        raise DocVaultError(
            "PG_CLIENT_MISSING",
            detail=f"{tool.name} --version did not report a version.",
        )
    return (int(match.group(1)), int(match.group(2)))


def require_client_version(tool: Path, server_version: str) -> None:
    """The client must be the same major and at least the server's minor."""
    server = tuple(int(part) for part in normalise_server_version(server_version).split(".")[:2])
    client = _tool_version(tool)
    if client[0] != server[0] or client < server:
        raise DocVaultError(
            "PG_CLIENT_TOO_OLD",
            detail=(
                f"{tool.name} {'.'.join(map(str, client))} is older than "
                f"server {'.'.join(map(str, server))}."
            ),
            remediation="Install the client tools that ship with PostgreSQL 18.",
        )


@contextlib.contextmanager
def _pgpass(context: BackupContext) -> Iterator[Path]:
    """Write a transient libpq password file, then remove it even on failure."""
    url = make_url(context.dsn)
    host = url.host or "localhost"
    port = url.port or 5432
    database = url.database or ""
    user = url.username or context.credential.role
    password = context.credential.password.replace("\\", "\\\\").replace(":", "\\:")
    path = context.paths.tmp / f"pgpass-{secrets.token_hex(8)}"
    context.paths.tmp.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(f"{host}:{port}:{database}:{user}:{password}\n")
            handle.flush()
            os.fsync(handle.fileno())
        yield path
    finally:
        path.unlink(missing_ok=True)


def _environment(pgpass: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PGPASSFILE"] = str(pgpass)
    env["PGCONNECT_TIMEOUT"] = str(CONNECT_TIMEOUT_SECONDS)
    env.pop("PGPASSWORD", None)
    return env


def read_latest(paths: VaultPaths) -> DumpPointer:
    """Read and validate ``LATEST``. A missing pointer is not an error for ``status``."""
    try:
        text = paths.latest_dump.read_text(encoding="utf-8")
    except OSError as exc:
        raise DocVaultError(
            "DUMP_NOT_FOUND",
            detail=f"No LATEST pointer in {paths.dump_dir}.",
            remediation="Run docvault backup to write the first dump.",
        ) from exc
    return DumpPointer.parse(text)


def write_latest(paths: VaultPaths, pointer: DumpPointer) -> None:
    """Replace ``LATEST`` atomically, after the dump itself is durable."""
    atomic_write(paths.latest_dump, pointer.serialise().encode("utf-8"))


def dump_path(paths: VaultPaths, name: str) -> Path:
    """Resolve a dump name inside ``index/db/``, refusing a path."""
    if Path(name).name != name or not FILENAME.match(name):
        raise DocVaultError("DUMP_INVALID", detail=f"Not a dump name: {name!r}.")
    return paths.dump_dir / name


def create_backup(
    context: BackupContext,
    *,
    pre_migration: bool = False,
    moment: datetime | None = None,
) -> DumpPointer:
    """Run ``pg_dump``, encrypt it, and only then move ``LATEST``."""
    created = moment or now_utc()
    name = dump_filename(created, pre_migration=pre_migration)
    final = dump_path(context.paths, name)
    if final.exists():
        raise DocVaultError("DUMP_INVALID", detail=f"{name} already exists.")
    pg_dump = tool_path(context.pg_bin_dir, "pg_dump")
    require_client_version(pg_dump, context.server_version)
    context.paths.dump_dir.mkdir(parents=True, exist_ok=True)
    part = context.paths.tmp / f"{name}.{secrets.token_hex(8)}.part"
    context.paths.tmp.mkdir(parents=True, exist_ok=True)

    with _pgpass(context) as pgpass:
        try:
            process = subprocess.Popen(
                [
                    str(pg_dump),
                    "--format=custom",
                    "--no-owner",
                    f"--dbname={context.dsn}",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_environment(pgpass),
            )
        except OSError as exc:
            raise DocVaultError("PG_DUMP_FAILED", detail=f"Cannot start pg_dump: {exc}") from exc
        if process.stdout is None:  # pragma: no cover - PIPE guarantees a pipe
            process.kill()
            raise DocVaultError("PG_DUMP_FAILED", detail="pg_dump produced no output pipe.")
        try:
            plaintext_bytes = dump.encrypt_stream(
                process.stdout,
                part,
                dump_key=context.dump_key,
            )
        finally:
            process.stdout.close()
        stderr = b""
        if process.stderr is not None:
            stderr = process.stderr.read()
            process.stderr.close()
        returncode = process.wait()

    if returncode != 0:
        part.unlink(missing_ok=True)
        message = stderr.decode("utf-8", "replace").strip().splitlines()
        raise DocVaultError(
            "PG_DUMP_FAILED",
            detail=message[-1] if message else f"pg_dump exited {returncode}.",
        )

    try:
        part.replace(final)
        _fsync(context.paths.dump_dir)
    except OSError as exc:
        part.unlink(missing_ok=True)
        raise DocVaultError("VAULT_UNWRITABLE", detail=f"Cannot finish {name}: {exc}") from exc

    pointer = DumpPointer(
        file=name,
        size=final.stat().st_size,
        plaintext_bytes=plaintext_bytes,
        sha256=dump.file_sha256(final),
        created_at=format_seconds(created),
        pg_version=normalise_server_version(context.server_version),
        schema_version=context.schema_version,
        vault_id=context.vault_id,
    )
    write_latest(context.paths, pointer)
    rotate(context.paths, keep=context.keep)
    return pointer


def _fsync(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def rotate(paths: VaultPaths, *, keep: int) -> list[str]:
    """Delete ordinary dumps beyond ``keep``. Never delete pre-migration dumps.

    Rotation is best effort: a dump that cannot be removed is reported by the
    next ``status`` as an extra file, which is better than failing a backup whose
    ``LATEST`` already points at a good dump.
    """
    ordinary = sorted(
        (
            path
            for path in paths.dump_dir.glob("docvault-*.dump.enc")
            if not path.name.endswith(f"{PRE_MIGRATION_SUFFIX}.dump.enc")
        ),
        key=lambda path: path.name,
    )
    removed: list[str] = []
    for path in ordinary[: max(0, len(ordinary) - keep)]:
        try:
            path.unlink()
        except OSError:
            continue
        removed.append(path.name)
    return removed


def dumps(paths: VaultPaths) -> list[Path]:
    """Every dump on disk, newest last. ``LATEST`` is not a dump."""
    return sorted(paths.dump_dir.glob("docvault-*.dump.enc"), key=lambda path: path.name)


def _check_file(paths: VaultPaths, pointer: DumpPointer) -> Path:
    path = dump_path(paths, pointer.file)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise DocVaultError(
            "DUMP_NOT_FOUND", detail=f"LATEST names {pointer.file}, which is missing."
        ) from exc
    if size != pointer.size:
        raise DocVaultError(
            "DUMP_MISMATCH",
            detail=f"{pointer.file} is {size} bytes; LATEST says {pointer.size}.",
        )
    if dump.file_sha256(path) != pointer.sha256:
        raise DocVaultError(
            "DUMP_MISMATCH", detail=f"{pointer.file} does not match the SHA-256 in LATEST."
        )
    return path


def _decrypt_to_scratch(context: BackupContext, path: Path) -> tuple[Path, int]:
    scratch = context.paths.tmp / f"restore-{secrets.token_hex(8)}.dump"
    context.paths.tmp.mkdir(parents=True, exist_ok=True)
    with path.open("rb") as source:
        plaintext_bytes = dump.decrypt_stream(source, scratch, dump_key=context.dump_key)
    return scratch, plaintext_bytes


def _run_restore(
    context: BackupContext,
    pg_restore: Path,
    scratch: Path,
    *,
    listing: bool,
) -> str:
    if listing:
        arguments = [str(pg_restore), "--no-owner", "--list", str(scratch)]
    else:
        arguments = [
            str(pg_restore),
            "--exit-on-error",
            "--no-owner",
            f"--dbname={context.dsn}",
            str(scratch),
        ]
    with _pgpass(context) as pgpass:
        try:
            result = subprocess.run(
                arguments,
                capture_output=True,
                text=True,
                env=_environment(pgpass),
                check=False,
                timeout=600,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DocVaultError(
                "PG_RESTORE_FAILED", detail=f"Cannot run pg_restore: {exc}"
            ) from exc
    if result.returncode != 0:
        message = result.stderr.strip().splitlines()
        raise DocVaultError(
            "PG_RESTORE_FAILED",
            detail=message[-1] if message else "pg_restore failed.",
        )
    return result.stdout


def restore_dump(
    context: BackupContext,
    *,
    name: str | None = None,
) -> RestoreResult:
    """Restore ``LATEST`` (or a named dump) into an empty database.

    For ``LATEST`` the pointer is checked before anything is decrypted: vault ID,
    size, and SHA-256. A dump named explicitly has no pointer, so its container
    tags are checked first and its identity is verified after the restore.
    """
    pointer: DumpPointer | None = None
    if name is None:
        pointer = read_latest(context.paths)
        if pointer.vault_id != context.vault_id:
            raise DocVaultError(
                "DUMP_MISMATCH",
                detail="LATEST belongs to a different vault.",
            )
        path = _check_file(context.paths, pointer)
    else:
        path = dump_path(context.paths, name)
        if not path.is_file():
            raise DocVaultError("DUMP_NOT_FOUND", detail=f"No dump named {name}.")
        latest = None
        with contextlib.suppress(DocVaultError):
            latest = read_latest(context.paths)
        if latest is not None and latest.file == name:
            pointer = latest
            if pointer.vault_id != context.vault_id:
                raise DocVaultError(
                    "DUMP_MISMATCH",
                    detail="LATEST belongs to a different vault.",
                )
            _check_file(context.paths, pointer)

    pg_restore = tool_path(context.pg_bin_dir, "pg_restore")
    require_client_version(pg_restore, context.server_version)
    scratch, plaintext_bytes = _decrypt_to_scratch(context, path)
    try:
        _run_restore(context, pg_restore, scratch, listing=False)
    finally:
        scratch.unlink(missing_ok=True)

    return RestoreResult(
        file=path.name,
        plaintext_bytes=plaintext_bytes,
        from_latest=pointer is not None,
    )


def list_dump(context: BackupContext, *, name: str | None = None) -> str:
    """Return ``pg_restore --list`` for a dump, after authenticating the container."""
    if name is None:
        pointer = read_latest(context.paths)
        if pointer.vault_id != context.vault_id:
            raise DocVaultError("DUMP_MISMATCH", detail="LATEST belongs to a different vault.")
        path = _check_file(context.paths, pointer)
    else:
        path = dump_path(context.paths, name)
        if not path.is_file():
            raise DocVaultError("DUMP_NOT_FOUND", detail=f"No dump named {name}.")
        latest = None
        with contextlib.suppress(DocVaultError):
            latest = read_latest(context.paths)
        if latest is not None and latest.file == name and latest.vault_id != context.vault_id:
            raise DocVaultError("DUMP_MISMATCH", detail="LATEST belongs to a different vault.")
    pg_restore = tool_path(context.pg_bin_dir, "pg_restore")
    require_client_version(pg_restore, context.server_version)
    scratch, _ = _decrypt_to_scratch(context, path)
    try:
        return _run_restore(context, pg_restore, scratch, listing=True)
    finally:
        scratch.unlink(missing_ok=True)
