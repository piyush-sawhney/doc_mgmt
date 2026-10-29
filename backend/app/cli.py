"""The ``docvault`` command-line entry point.

The CLI is a thin process boundary: it loads validated settings, prompts for
the passphrase when a human is present, and calls the same vault code the API
uses. It never logs or stores the passphrase.
"""

from __future__ import annotations

import argparse
import getpass
import secrets
import shutil
import subprocess
import sys
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path

import uvicorn
from sqlalchemy import delete, select, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session

from app.core.config import LoadedSettings, load_settings, write_vault_root
from app.core.errors import DocVaultError
from app.core.logging import configure_logging
from app.core.tls import TlsMaterial, generate_tls, public_fingerprint, tls_directory
from app.crypto.keys import VaultKeys, derive_keys, unwrap_vmk
from app.crypto.passphrase import validate_passphrase
from app.db import backup, bootstrap, connect, migrate
from app.db.credentials import (
    Credential,
    credential_path,
    load_credential,
    save_credential,
)
from app.db.enums import RoleName
from app.db.models.identity import Session as AuthSession
from app.db.models.identity import User
from app.db.provision import DEFAULT_DATABASE, DEFAULT_ROLE, provision
from app.main import create_app
from app.services.audit import append_event as append_audit_event
from app.services.auth import create_user
from app.vault import audit
from app.vault.control import VaultControlServer, send_control_command
from app.vault.init import create_vault
from app.vault.inspect import inspect
from app.vault.layout import probe_root, vault_paths
from app.vault.manifest import load as load_manifest
from app.vault.manifest import load_and_verify, validate_structure
from app.vault.session import VaultManager
from app.version import __version__

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


def _add_config_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        type=Path,
        dest="config_override",
        default=None,
        help="Path to docvault.toml (default: DOCVAULT_CONFIG or the OS path)",
    )


def _load(args: argparse.Namespace) -> LoadedSettings:
    path = args.config_override or args.config
    return load_settings(path)


def _prompt_passphrase(*, confirm: bool) -> str:
    first = getpass.getpass("Vault passphrase: ")
    if confirm:
        second = getpass.getpass("Repeat passphrase: ")
        if first != second:
            raise DocVaultError("PASSPHRASE_MISMATCH")
    if not first:
        raise DocVaultError("PASSPHRASE_POLICY", detail="The passphrase cannot be empty.")
    return first


def _load_extra() -> object:
    return object()


def _admin_dsn(loaded: LoadedSettings, override: str | None) -> str:
    """Return a DSN for the PostgreSQL admin, prompting for a password if needed."""
    if override:
        return override
    url = make_url(loaded.settings.database.dsn)
    if url.password is not None:
        raise DocVaultError(
            "CONFIG_INVALID",
            detail="database.dsn must not carry a password.",
            remediation="Leave the password out of docvault.toml; the app stores it.",
        )
    host = url.host or "local socket"
    password = getpass.getpass(f"PostgreSQL admin password for postgres@{host} (blank for trust): ")
    admin = url.set(
        username="postgres",
        password=password or None,
        database="postgres",
    )
    return admin.render_as_string(hide_password=False)


def _provision_database(loaded: LoadedSettings, args: argparse.Namespace) -> Credential:
    """Create the role and database, then store the generated credential."""
    if loaded.path is None:  # pragma: no cover - load_settings always sets it
        raise DocVaultError("CONFIG_INVALID", detail="init needs a configuration file.")
    url = make_url(loaded.settings.database.dsn)
    if url.password is not None:
        raise DocVaultError(
            "CONFIG_INVALID",
            detail="database.dsn must not carry a password.",
            remediation="Leave the password out of docvault.toml; the app stores it.",
        )
    role = url.username or DEFAULT_ROLE
    database = url.database or DEFAULT_DATABASE
    password = secrets.token_urlsafe(32)
    result = provision(
        _admin_dsn(loaded, args.admin_dsn),
        database=database,
        role=role,
        password=password,
    )
    credential = Credential(role=role, password=password)
    save_credential(
        credential_path(loaded.path),
        credential,
        environment=loaded.settings.environment,
    )
    action = "created" if result.role_created or result.database_created else "adopted"
    print(f"database: {result.database} ({action}), role {result.role}")
    return credential


def _unlock(manager: VaultManager) -> None:
    """Unlock with a passphrase from the terminal, with no confirmation prompt."""
    manager.unlock(_prompt_passphrase(confirm=False))


def _keys_without_lock(root: Path, passphrase: str) -> VaultKeys:
    """Derive keys read-only, for `doctor`, which must not take the writer lock."""
    wrapped = vault_paths(root).kek.read_bytes()
    vmk = unwrap_vmk(wrapped, passphrase)
    keys = derive_keys(vmk)
    load_and_verify(vault_paths(root).manifest, keys)
    return keys


def _backup_context(
    loaded: LoadedSettings,
    manager: VaultManager,
    credential: Credential,
) -> backup.BackupContext:
    """Resolve the schema and server version, then package everything a dump needs."""
    engine = bootstrap.engine_for(loaded, credential)
    try:
        info = connect.require_supported_server(engine)
        with engine.connect() as connection:
            identity = bootstrap.check_bootstrap(
                connection,
                meta_key=manager.keys.meta_key,
                vault_id=manager.manifest.vault_id,
            )
    finally:
        engine.dispose()
    return backup.BackupContext(
        paths=manager.paths,
        dsn=loaded.settings.database.dsn,
        credential=credential,
        pg_bin_dir=loaded.settings.database.pg_bin_dir,
        dump_key=manager.keys.dump_key,
        vault_id=manager.manifest.vault_id,
        schema_version=identity.schema_version,
        server_version=info.version,
        keep=loaded.settings.backup.keep,
    )


def _restore_context(
    loaded: LoadedSettings,
    manager: VaultManager,
    credential: Credential,
) -> backup.BackupContext:
    """A context for restoring: the target database is empty, so it has no identity yet."""
    engine = bootstrap.engine_for(loaded, credential)
    try:
        info = connect.require_supported_server(engine)
    finally:
        engine.dispose()
    return backup.BackupContext(
        paths=manager.paths,
        dsn=loaded.settings.database.dsn,
        credential=credential,
        pg_bin_dir=loaded.settings.database.pg_bin_dir,
        dump_key=manager.keys.dump_key,
        vault_id=manager.manifest.vault_id,
        schema_version=manager.manifest.schema_version,
        server_version=info.version,
        keep=loaded.settings.backup.keep,
    )


def _dump(
    loaded: LoadedSettings,
    manager: VaultManager,
    credential: Credential,
    *,
    pre_migration: bool = False,
) -> backup.DumpPointer:
    """Write one dump, audit it, and print the two facts an operator needs."""
    context = _backup_context(loaded, manager, credential)
    pointer = backup.create_backup(context, pre_migration=pre_migration)
    manager.record_event(
        "database.dump",
        object_type="database",
        object_id=pointer.vault_id,
        detail={
            "file": pointer.file,
            "sha256": pointer.sha256,
            "size": pointer.size,
            "plaintext_bytes": pointer.plaintext_bytes,
            "pre_migration": pointer.pre_migration,
        },
    )
    label = "pre-migration dump" if pointer.pre_migration else "dump"
    print(f"{label}: {pointer.file} ({pointer.size} bytes, sha256 {pointer.sha256[:12]}…)")
    return pointer


def _read_only_context(
    loaded: LoadedSettings,
    root: Path,
    keys: VaultKeys,
    credential: Credential,
) -> backup.BackupContext:
    """Build a context without the writer lock, for ``dump-list``."""
    identity = validate_structure(load_manifest(vault_paths(root).manifest))
    engine = bootstrap.engine_for(loaded, credential)
    try:
        info = connect.require_supported_server(engine)
    finally:
        engine.dispose()
    return backup.BackupContext(
        paths=vault_paths(root),
        dsn=loaded.settings.database.dsn,
        credential=credential,
        pg_bin_dir=loaded.settings.database.pg_bin_dir,
        dump_key=keys.dump_key,
        vault_id=identity.vault_id,
        schema_version=identity.schema_version,
        server_version=info.version,
        keep=loaded.settings.backup.keep,
    )


def _migrate_and_seed(
    loaded: LoadedSettings, manager: VaultManager, credential: Credential
) -> None:
    """Dump if a migration is pending, apply it, then seed and stamp the identity."""
    revision = _schema_revision(loaded, credential)
    if revision is not None and revision != migrate.head_revision():
        _dump(loaded, manager, credential, pre_migration=True)
    bootstrap.migrate_database(loaded, credential)
    engine = bootstrap.engine_for(loaded, credential)
    try:
        with engine.connect() as connection:
            result = bootstrap.bootstrap_database(
                connection,
                meta_key=manager.keys.meta_key,
                vault_id=manager.manifest.vault_id,
            )
    finally:
        engine.dispose()
    manager.record_event(
        "database.migrate",
        object_type="database",
        object_id=manager.manifest.vault_id,
        detail={
            "schema_version": result.schema_version,
            "categories_inserted": result.seed.categories_inserted,
            "types_inserted": result.seed.types_inserted,
        },
    )
    print(
        f"database: schema {result.schema_version}, "
        f"{result.seed.categories_total} categories, {result.seed.types_total} types "
        f"({result.seed.inserted} inserted)"
    )


def _schema_revision(loaded: LoadedSettings, credential: Credential) -> str | None:
    engine = bootstrap.engine_for(loaded, credential)
    try:
        with engine.connect() as connection:
            return migrate.current_revision(connection)
    finally:
        engine.dispose()


def _cmd_init(args: argparse.Namespace) -> int:
    loaded = _load(args)
    settings = loaded.settings
    root = args.vault.expanduser().resolve()
    if loaded.path is None:  # pragma: no cover - load_settings always sets it
        raise DocVaultError("CONFIG_INVALID", detail="init needs a configuration file.")

    credential: Credential | None = None
    if args.reuse_vault:
        if not (root / "manifest.json").is_file():
            raise DocVaultError(
                "VAULT_NOT_FOUND",
                detail=f"No vault at {root}; run init without --reuse-vault first.",
            )
        credential = _provision_database(loaded, args)
        print("vault: reused; manifest and key file were not touched")
        return EXIT_OK

    if not args.no_database:
        credential = _provision_database(loaded, args)

    passphrase = _prompt_passphrase(confirm=True)
    validate_passphrase(passphrase)
    max_file_bytes = (
        args.max_file_mb * 1024 * 1024
        if args.max_file_mb is not None
        else settings.limits.max_file_bytes
    )
    result = create_vault(
        root,
        passphrase=passphrase,
        display_name=args.display_name,
        max_file_bytes=max_file_bytes,
        app_version=__version__,
        notes=args.notes,
    )
    material: TlsMaterial | None = None
    if not args.no_tls:
        directory = tls_directory(
            environment=settings.environment,
            config_path=loaded.path,
            vault_root=root,
        )
        material = generate_tls(directory, bind=settings.server.bind, force=args.force_tls)
    write_vault_root(loaded.path, root)

    if credential is not None:
        manager = VaultManager(root, app_version=__version__)
        try:
            manager.open()
            manager.unlock(passphrase)
            _migrate_and_seed(loaded, manager, credential)
            _dump(loaded, manager, credential)
        finally:
            manager.close()

    print(f"vault_root: {result.root}")
    print(f"vault_id: {result.vault_id}")
    print(f"display_name: {result.display_name}")
    print(f"key_fingerprint: {result.key_fingerprint}")
    if material is not None:
        print(f"tls_directory: {material.directory}")
        print(f"ca_fingerprint: {material.ca_fingerprint}")
        print(f"server_fingerprint: {material.server_fingerprint}")
    if credential is None:
        print("database: not provisioned (init --no-database)")
    print("next: seal the passphrase in two envelopes before uploading a document")
    return EXIT_OK


def _cmd_status(args: argparse.Namespace) -> int:
    loaded = _load(args)
    settings = loaded.settings
    root = settings.require_vault_root()
    tls_dir = tls_directory(
        environment=settings.environment,
        config_path=loaded.path,
        vault_root=root,
    )
    info = inspect(root, tls_directory=tls_dir)
    print(f"vault_root: {info.paths.root}")
    print(f"vault_id: {info.manifest.vault_id}")
    print(f"display_name: {info.manifest.display_name}")
    print(f"format_version: {info.manifest.format_version}")
    print(f"schema_version: {info.manifest.schema_version}")
    print(f"key_fingerprint: {info.manifest.key_fingerprint}")
    url = make_url(settings.database.dsn)
    if loaded.path is not None and credential_path(loaded.path).is_file():
        print(f"database: {url.database or DEFAULT_DATABASE} (credential present)")
    else:
        print(f"database: {url.database or DEFAULT_DATABASE} (credential missing)")
    lock = info.lock.record
    if lock is None:
        print("lock: free")
    else:
        state = "stale" if info.lock.stale else "held"
        print(f"lock: {state} by pid {lock.pid} since {lock.started_at.isoformat()}")
    print(f"blob_count: {info.blob_count}")
    print(f"audit_entries: {info.audit_entries}")
    if info.last_dump:
        name = info.last_dump.get("file", "unknown")
        created = info.last_dump.get("created_at", "unknown")
        print(f"last_dump: {name} at {created}")
    else:
        print("last_dump: none")
    if info.tls_ca is not None:
        print(f"ca_fingerprint: {public_fingerprint(info.tls_ca)}")
    if info.tls_server is not None:
        print(f"server_fingerprint: {public_fingerprint(info.tls_server)}")
    chain = audit.verify_chain(info.paths.audit_dir)
    print(f"audit_chain: {'ok' if chain.ok else 'broken'} ({chain.entries} entries)")
    if not chain.ok:
        print(f"audit_problem: {chain.detail}")
    return EXIT_OK


def _check(name: str, ok: bool, detail: str) -> tuple[str, bool, str]:
    return (name, ok, detail)


def _pg_version(executable: Path) -> str | None:
    try:
        result = subprocess.run(
            [str(executable), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or result.stderr.strip()


def _doctor_vault_key(checks: list[tuple[str, bool, str]], root: Path) -> bytes | None:
    if not sys.stdin.isatty():
        checks.append(
            _check("vault key", False, "a terminal is needed to verify the database identity")
        )
        return None
    try:
        passphrase = _prompt_passphrase(confirm=False)
        meta_key = _keys_without_lock(root, passphrase).meta_key
    except DocVaultError as exc:
        checks.append(_check("vault key", False, f"{exc.code}: {exc.detail}"))
        return None
    checks.append(_check("vault key", True, "manifest signature verified"))
    return meta_key


def _doctor_identity(
    checks: list[tuple[str, bool, str]],
    engine: Engine,
    *,
    meta_key: bytes | None,
    vault_id: str | None,
) -> None:
    if meta_key is None or vault_id is None:
        return
    try:
        with engine.connect() as connection:
            identity = bootstrap.check_bootstrap(
                connection,
                meta_key=meta_key,
                vault_id=vault_id,
            )
    except DocVaultError as exc:
        checks.append(_check("database identity", False, f"{exc.code}: {exc.detail}"))
        return
    checks.append(
        _check(
            "database identity",
            True,
            f"{identity.vault_id} (schema {identity.schema_version})",
        )
    )


def _doctor_database(
    checks: list[tuple[str, bool, str]],
    loaded: LoadedSettings,
    *,
    meta_key: bytes | None,
    vault_id: str | None,
) -> None:
    if loaded.path is None:  # pragma: no cover - load_settings always sets it
        checks.append(_check("database credential", False, "no configuration file"))
        return
    try:
        credential = load_credential(credential_path(loaded.path))
    except DocVaultError as exc:
        checks.append(_check("database credential", False, f"{exc.code}: {exc.detail}"))
        return
    checks.append(_check("database credential", True, str(credential_path(loaded.path))))

    engine = bootstrap.engine_for(loaded, credential)
    try:
        try:
            info = connect.require_supported_server(engine)
        except DocVaultError as exc:
            checks.append(_check("database server", False, f"{exc.code}: {exc.detail}"))
            return
        checks.append(_check("database server", True, f"PostgreSQL {info.version}"))
        client_problem: str | None = None
        for name in ("pg_dump", "pg_restore"):
            try:
                tool = backup.tool_path(loaded.settings.database.pg_bin_dir, name)
                backup.require_client_version(tool, info.version)
            except DocVaultError as exc:
                client_problem = f"{exc.code}: {exc.detail}"
                break
        checks.append(
            _check(
                "postgres client",
                client_problem is None,
                client_problem or f"pg_dump and pg_restore are at least {info.version}",
            )
        )
        _doctor_identity(checks, engine, meta_key=meta_key, vault_id=vault_id)
    finally:
        engine.dispose()


def _cmd_doctor(args: argparse.Namespace) -> int:
    loaded = _load(args)
    settings = loaded.settings
    root = settings.require_vault_root()
    checks: list[tuple[str, bool, str]] = []
    checks.append(_check("configuration", True, str(loaded.path)))
    checks.append(_check("vault root", root.is_dir(), str(root)))

    vault_id: str | None = None
    if (root / "manifest.json").is_file():
        try:
            identity = validate_structure(load_manifest(root / "manifest.json"))
            vault_id = identity.vault_id
            checks.append(
                _check("manifest", True, f"{identity.vault_id} (format {identity.format_version})")
            )
        except DocVaultError as exc:
            checks.append(_check("manifest", False, f"{exc.code}: {exc.detail}"))
    else:
        checks.append(_check("manifest", False, "manifest.json is missing"))

    try:
        report = probe_root(root, create=False)
        checks.append(
            _check(
                "filesystem",
                True,
                f"{report.filesystem}, case-insensitive={report.case_insensitive}",
            )
        )
    except DocVaultError as exc:
        checks.append(_check("filesystem", False, f"{exc.code}: {exc.detail}"))

    kek = vault_paths(root).kek
    checks.append(_check("key file", kek.is_file() and kek.stat().st_size == 96, str(kek)))

    chain = audit.verify_chain(vault_paths(root).audit_dir)
    checks.append(
        _check(
            "audit chain",
            chain.ok,
            f"{chain.entries} entries" if chain.ok else chain.detail,
        )
    )

    pg_bin = settings.database.pg_bin_dir
    dump = shutil.which("pg_dump", path=str(pg_bin)) or shutil.which("pg_dump")
    restore = shutil.which("pg_restore", path=str(pg_bin)) or shutil.which("pg_restore")
    if dump is None or restore is None:
        checks.append(_check("postgres tools", False, "pg_dump or pg_restore not found"))
    else:
        version = _pg_version(Path(dump))
        ok = version is not None and "18." in version
        checks.append(_check("postgres tools", ok, version or "cannot read version"))

    tls_dir = tls_directory(
        environment=settings.environment,
        config_path=loaded.path,
        vault_root=root,
    )
    ca = tls_dir / "docvault-ca.crt"
    server = tls_dir / "docvault-server.crt"
    checks.append(
        _check(
            "tls material",
            ca.is_file() and server.is_file(),
            str(tls_dir),
        )
    )

    meta_key = _doctor_vault_key(checks, root)
    _doctor_database(checks, loaded, meta_key=meta_key, vault_id=vault_id)

    width = max(len(name) for name, _, _ in checks)
    failures = 0
    for name, ok, detail in checks:
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1
        print(f"{status}  {name.ljust(width)}  {detail}")
    if failures:
        print(f"\n{failures} check(s) failed")
        return EXIT_ERROR
    return EXIT_OK


def _cmd_unlock(args: argparse.Namespace) -> int:
    loaded = _load(args)
    passphrase = _prompt_passphrase(confirm=False)
    result = send_control_command(
        loaded.settings.require_vault_root(),
        "unlock",
        passphrase=passphrase,
    )
    print(f"unlocked: {result['vault_id']}")
    print(f"key_fingerprint: {result['key_fingerprint']}")
    return EXIT_OK


def _cmd_migrate(args: argparse.Namespace) -> int:
    loaded = _load(args)
    settings = loaded.settings
    root = settings.require_vault_root()
    manager = VaultManager(root, app_version=__version__, force_lock=args.force_lock)
    try:
        manager.open()
        _unlock(manager)
        credential = bootstrap.credential_for(loaded)
        _migrate_and_seed(loaded, manager, credential)
        return EXIT_OK
    finally:
        manager.close()


def _cmd_backup(args: argparse.Namespace) -> int:
    loaded = _load(args)
    root = loaded.settings.require_vault_root()
    manager = VaultManager(root, app_version=__version__, force_lock=args.force_lock)
    try:
        manager.open()
        _unlock(manager)
        credential = bootstrap.credential_for(loaded)
        _dump(loaded, manager, credential)
        return EXIT_OK
    finally:
        manager.close()


def _cmd_restore(args: argparse.Namespace) -> int:
    loaded = _load(args)
    root = args.vault.expanduser().resolve()
    manager = VaultManager(root, app_version=__version__, force_lock=args.force_lock)
    try:
        manager.open()
        _unlock(manager)
        credential = bootstrap.credential_for(loaded)
        context = _restore_context(loaded, manager, credential)
        result = backup.restore_dump(context, name=args.dump)
        engine = bootstrap.engine_for(loaded, credential)
        try:
            with engine.connect() as connection:
                identity = bootstrap.check_bootstrap(
                    connection,
                    meta_key=manager.keys.meta_key,
                    vault_id=manager.manifest.vault_id,
                )
        except DocVaultError as exc:
            manager.record_event(
                "vault.restore.deny",
                object_type="vault",
                object_id=manager.manifest.vault_id,
                outcome="deny",
                detail={"file": result.file, "reason": exc.code},
            )
            raise
        finally:
            engine.dispose()
        manager.record_event(
            "vault.restore",
            object_type="vault",
            object_id=manager.manifest.vault_id,
            detail={
                "file": result.file,
                "plaintext_bytes": result.plaintext_bytes,
                "schema_version": identity.schema_version,
                "from_latest": result.from_latest,
            },
        )
        print(f"restored: {result.file} ({result.plaintext_bytes} plaintext bytes)")
        print(f"database: schema {identity.schema_version}, vault {identity.vault_id}")
        print("next: run docvault verify --deep, then start the service")
        return EXIT_OK
    finally:
        manager.close()


def _cmd_dump_list(args: argparse.Namespace) -> int:
    loaded = _load(args)
    root = loaded.settings.require_vault_root()
    passphrase = _prompt_passphrase(confirm=False)
    keys = _keys_without_lock(root, passphrase)
    credential = bootstrap.credential_for(loaded)
    context = _read_only_context(loaded, root, keys, credential)
    listing = backup.list_dump(context, name=args.dump)
    print(listing, end="" if listing.endswith("\n") else "\n")
    return EXIT_OK


def _cmd_user_create(args: argparse.Namespace) -> int:
    """Create the initial admin account before browser-based administration."""
    loaded = _load(args)
    root = loaded.settings.require_vault_root()
    manager = VaultManager(root, app_version=__version__)
    try:
        manager.open()
        _unlock(manager)
        credential = bootstrap.credential_for(loaded)
        engine = bootstrap.engine_for(loaded, credential)
        temporary_password = secrets.token_urlsafe(18)
        try:
            connect.require_supported_server(engine)
            with engine.begin() as connection:
                bootstrap.check_bootstrap(
                    connection,
                    meta_key=manager.keys.meta_key,
                    vault_id=manager.manifest.vault_id,
                )
                connection.execute(text("SELECT pg_advisory_xact_lock(1146309705)"))
                existing_user = connection.execute(select(User.id).limit(1)).first()
                if existing_user is not None:
                    raise DocVaultError(
                        "FORBIDDEN",
                        detail="CLI user creation is only available before the first account.",
                        remediation="Sign in as an administrator and use POST /api/v1/users.",
                    )
                if RoleName.ADMIN not in args.role:
                    raise DocVaultError(
                        "VALIDATION_FAILED",
                        detail="The initial account must include the admin role.",
                    )
                with Session(bind=connection) as session:
                    user = create_user(
                        session,
                        manager.keys,
                        username=args.username,
                        display_name=args.display_name or args.username,
                        password=temporary_password,
                        roles=tuple(args.role),
                        actor_id=None,
                        source_ip=None,
                    )
                    user_id = user.id
        finally:
            engine.dispose()
        manager.record_event(
            "user.create",
            object_type="user",
            object_id=str(user_id),
            detail={"source": "initial_cli"},
        )
        print(f"user: {args.username}")
        print(f"user_id: {user_id}")
        print(f"temporary_password: {temporary_password}")
        print("must_change_password: yes")
        return EXIT_OK
    finally:
        manager.close()


def _cmd_lock(_args: argparse.Namespace) -> int:
    loaded = _load(_args)
    send_control_command(loaded.settings.require_vault_root(), "lock")
    print("locked: the running service dropped its vault keys")
    return EXIT_OK


def _resolve_tls(loaded: LoadedSettings, root: Path) -> tuple[Path | None, Path | None]:
    directory = tls_directory(
        environment=loaded.settings.environment,
        config_path=loaded.path,
        vault_root=root,
    )
    key = directory / "docvault-server.key"
    cert = directory / "docvault-server.crt"
    if key.is_file() and cert.is_file():
        return key, cert
    return None, None


def _cmd_serve(args: argparse.Namespace) -> int:
    loaded = _load(args)
    settings = loaded.settings
    configure_logging(settings.log.level)
    root = settings.require_vault_root()
    manager = VaultManager(root, app_version=__version__, force_lock=args.force_lock)
    manager.open()
    if manager.locked:
        if settings.vault.auto_unlock:
            raise DocVaultError(
                "CONFIG_INVALID",
                detail="Automatic unlock is not available in this build.",
                remediation="Use manual unlock, or wait for the DPAPI/keyring slice.",
            )
        passphrase = _prompt_passphrase(confirm=False)
        manager.unlock(passphrase)
    key, cert = _resolve_tls(loaded, root)
    if key is None or cert is None:
        raise DocVaultError(
            "CONFIG_INVALID",
            detail="No TLS certificate found.",
            remediation="Run docvault init to generate the CA and server certificate.",
        )
    try:
        credential = bootstrap.credential_for(loaded)
        engine = bootstrap.engine_for(loaded, credential)
        try:
            connect.require_supported_server(engine)
            with engine.connect() as connection:
                bootstrap.check_bootstrap(
                    connection,
                    meta_key=manager.keys.meta_key,
                    vault_id=manager.manifest.vault_id,
                )
        finally:
            engine.dispose()
        api_engine = bootstrap.engine_for(loaded, credential)
        app = create_app(
            loaded=loaded,
            vault=manager,
            db_engine=api_engine,
            app_version=__version__,
        )
        print(f"serving on https://{settings.server.bind}:{settings.server.port}")

        def lock_service_sessions() -> int:
            with api_engine.begin() as connection:
                deleted = connection.execute(delete(AuthSession))
                revoked = max(deleted.rowcount or 0, 0)
                append_audit_event(
                    connection,
                    action="vault.lock",
                    object_type="vault",
                    object_id=uuid.UUID(manager.manifest.vault_id),
                    actor_id=None,
                    detail={"revoked_sessions": revoked},
                )
                return revoked

        with VaultControlServer(manager, on_lock=lock_service_sessions):
            uvicorn.run(
                app,
                host=settings.server.bind,
                port=settings.server.port,
                ssl_certfile=str(cert),
                ssl_keyfile=str(key),
                log_config=None,
                access_log=False,
            )
    finally:
        manager.close()
    return EXIT_OK


def _simple_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    help_text: str,
    func: Callable[[argparse.Namespace], int],
) -> argparse.ArgumentParser:
    """Register a command that needs only ``--config``."""
    parser = subparsers.add_parser(name, help=help_text)
    _add_config_argument(parser)
    parser.set_defaults(func=func)
    return parser


def _add_user_commands(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register local account bootstrap commands."""
    user = subparsers.add_parser("user", help="Manage accounts")
    user_commands = user.add_subparsers(dest="user_command", required=True)
    create_user_parser = user_commands.add_parser(
        "create", help="Create the first administrator account"
    )
    _add_config_argument(create_user_parser)
    create_user_parser.add_argument("--username", required=True)
    create_user_parser.add_argument("--display-name", default=None)
    create_user_parser.add_argument(
        "--role",
        action="append",
        type=RoleName,
        choices=list(RoleName),
        required=True,
    )
    create_user_parser.set_defaults(func=_cmd_user_create)


def build_parser() -> argparse.ArgumentParser:
    """Build the command tree. Kept separate so tests can inspect it."""
    parser = argparse.ArgumentParser(
        prog="docvault",
        description="Encrypted, offline document management for a small office.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", type=Path, default=None, help="Path to docvault.toml")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="Create a vault and its TLS material")
    _add_config_argument(init)
    init.add_argument("--vault", type=Path, required=True, help="Absolute path for the vault")
    init.add_argument(
        "--display-name", default="DocVault", help="Human name recorded in the manifest"
    )
    init.add_argument("--notes", default="", help="Free-text note recorded in the manifest")
    init.add_argument("--max-file-mb", type=int, default=None, help="Upload limit in MiB")
    init.add_argument("--force-tls", action="store_true", help="Replace existing TLS material")
    init.add_argument("--no-tls", action="store_true", help="Do not generate TLS (tests only)")
    init.add_argument(
        "--admin-dsn",
        default=None,
        help="PostgreSQL admin DSN; the password is prompted for when omitted",
    )
    init.add_argument(
        "--no-database",
        action="store_true",
        help="Create only the vault and TLS; do not provision PostgreSQL",
    )
    init.add_argument(
        "--reuse-vault",
        action="store_true",
        help="Re-create the database role and credential for an existing vault",
    )
    init.set_defaults(func=_cmd_init)

    _simple_command(subparsers, "status", "Show vault identity, lock, and counts", _cmd_status)
    _simple_command(subparsers, "doctor", "Check the environment one item at a time", _cmd_doctor)
    _simple_command(
        subparsers, "unlock", "Verify the passphrase and unwrap the vault key", _cmd_unlock
    )

    migrate = subparsers.add_parser("migrate", help="Apply migrations, then seed the catalogue")
    _add_config_argument(migrate)
    migrate.add_argument("--force-lock", action="store_true", help="Take over a stale vault lock")
    migrate.set_defaults(func=_cmd_migrate)

    backup_parser = subparsers.add_parser("backup", help="Write an encrypted database dump")
    _add_config_argument(backup_parser)
    backup_parser.add_argument(
        "--force",
        action="store_true",
        help="Accepted for the operator checklist; every backup is forced in this build",
    )
    backup_parser.add_argument(
        "--force-lock", action="store_true", help="Take over a stale vault lock"
    )
    backup_parser.set_defaults(func=_cmd_backup)

    restore = subparsers.add_parser("restore", help="Restore a dump into an empty database")
    _add_config_argument(restore)
    restore.add_argument("--vault", type=Path, required=True, help="Absolute path of the vault")
    restore.add_argument("--dump", default=None, help="Dump file name; defaults to LATEST")
    restore.add_argument("--force-lock", action="store_true", help="Take over a stale vault lock")
    restore.set_defaults(func=_cmd_restore)

    dump_list = subparsers.add_parser(
        "dump-list", help="Print the table of contents of an encrypted dump"
    )
    _add_config_argument(dump_list)
    dump_list.add_argument("--dump", default=None, help="Dump file name; defaults to LATEST")
    dump_list.set_defaults(func=_cmd_dump_list)

    _add_user_commands(subparsers)

    _simple_command(subparsers, "lock", "Drop the vault key from a running service", _cmd_lock)

    serve = _simple_command(subparsers, "serve", "Run the HTTPS API", _cmd_serve)
    serve.add_argument("--force-lock", action="store_true", help="Take over a stale vault lock")
    serve.set_defaults(func=_cmd_serve)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one command and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except DocVaultError as exc:
        print(f"{exc.code}: {exc.detail}", file=sys.stderr)
        for item in exc.fields:
            print(f"  {item.get('field')}: {item.get('message')}", file=sys.stderr)
        if exc.remediation:
            print(f"fix: {exc.remediation}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
