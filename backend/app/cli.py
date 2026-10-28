"""The ``docvault`` command-line entry point.

The CLI is a thin process boundary: it loads validated settings, prompts for
the passphrase when a human is present, and calls the same vault code the API
uses. It never logs or stores the passphrase.
"""

from __future__ import annotations

import argparse
import getpass
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from app.core.config import LoadedSettings, load_settings, write_vault_root
from app.core.errors import DocVaultError
from app.core.logging import configure_logging
from app.core.tls import TlsMaterial, generate_tls, public_fingerprint, tls_directory
from app.crypto.passphrase import validate_passphrase
from app.main import create_app
from app.vault import audit
from app.vault.init import create_vault
from app.vault.inspect import inspect
from app.vault.layout import probe_root, vault_paths
from app.vault.manifest import load as load_manifest
from app.vault.manifest import validate_structure
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


def _cmd_init(args: argparse.Namespace) -> int:
    loaded = _load(args)
    settings = loaded.settings
    root = args.vault.expanduser().resolve()
    if loaded.path is None:  # pragma: no cover - load_settings always sets it
        raise DocVaultError("CONFIG_INVALID", detail="init needs a configuration file.")
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

    print(f"vault_root: {result.root}")
    print(f"vault_id: {result.vault_id}")
    print(f"display_name: {result.display_name}")
    print(f"key_fingerprint: {result.key_fingerprint}")
    if material is not None:
        print(f"tls_directory: {material.directory}")
        print(f"ca_fingerprint: {material.ca_fingerprint}")
        print(f"server_fingerprint: {material.server_fingerprint}")
    print("database: not provisioned by this build (see docs/17-implementation.md)")
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


def _cmd_doctor(args: argparse.Namespace) -> int:
    loaded = _load(args)
    settings = loaded.settings
    root = settings.require_vault_root()
    checks: list[tuple[str, bool, str]] = []
    checks.append(_check("configuration", True, str(loaded.path)))
    checks.append(_check("vault root", root.is_dir(), str(root)))

    if (root / "manifest.json").is_file():
        try:
            identity = validate_structure(load_manifest(root / "manifest.json"))
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
    checks.append(
        _check(
            "database connection",
            False,
            f"not checked by this build; DSN {settings.database.dsn}",
        )
    )

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
    settings = loaded.settings
    manager = VaultManager(settings.require_vault_root(), app_version=__version__)
    try:
        manager.open()
        passphrase = _prompt_passphrase(confirm=False)
        identity = manager.unlock(passphrase)
        print(f"unlocked: {identity.vault_id}")
        print(f"key_fingerprint: {identity.key_fingerprint}")
        print("note: this build verifies the passphrase locally; live unlock IPC is pending")
        return EXIT_OK
    finally:
        manager.close()


def _cmd_lock(_args: argparse.Namespace) -> int:
    print("lock: a running service keeps its key in its own memory; IPC is pending in this build")
    print("stop the service to drop the key")
    return EXIT_ERROR


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
    app = create_app(loaded=loaded, vault=manager, app_version=__version__)
    print(f"serving on https://{settings.server.bind}:{settings.server.port}")
    try:
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
    init.set_defaults(func=_cmd_init)

    status = subparsers.add_parser("status", help="Show vault identity, lock, and counts")
    _add_config_argument(status)
    status.set_defaults(func=_cmd_status)

    doctor = subparsers.add_parser("doctor", help="Check the environment one item at a time")
    _add_config_argument(doctor)
    doctor.set_defaults(func=_cmd_doctor)

    unlock = subparsers.add_parser("unlock", help="Verify the passphrase and unwrap the vault key")
    _add_config_argument(unlock)
    unlock.set_defaults(func=_cmd_unlock)

    lock = subparsers.add_parser("lock", help="Drop the vault key from a running service")
    _add_config_argument(lock)
    lock.set_defaults(func=_cmd_lock)

    serve = subparsers.add_parser("serve", help="Run the HTTPS API")
    _add_config_argument(serve)
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
