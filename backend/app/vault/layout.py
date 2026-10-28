"""Vault folder layout, permissions, atomic writes, and filesystem probes.

The layout and the probes are compatibility and safety contracts from
``docs/03-vault-format.md`` §2 and §7. A vault that lives on a synced or
network folder looks fine until the first power cut, so opening one refuses
rather than warns.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from app.core.errors import DocVaultError

MANIFEST_NAME: Final = "manifest.json"
KEK_RELATIVE: Final = "keys/kek.wrapped"
LOCK_NAME: Final = ".lock"

REQUIRED_DIRS: Final = (
    "keys",
    "blobs",
    "index/db",
    "audit",
    "journal",
    "tmp",
    "trash",
)

# Filesystems that break atomic rename, fsync, or advisory locking.
NETWORK_FILESYSTEMS: Final = frozenset(
    {
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "smbfs",
        "fuse",
        "fuse.sshfs",
        "fuse.rclone",
        "sshfs",
        "9p",
        "davfs",
        "afs",
        "ceph",
        "glusterfs",
        "lustre",
        "gpfs",
    }
)


@dataclass(frozen=True, slots=True)
class VaultPaths:
    """Every path inside a vault, derived from one absolute root."""

    root: Path

    @property
    def manifest(self) -> Path:
        return self.root / MANIFEST_NAME

    @property
    def kek(self) -> Path:
        return self.root / KEK_RELATIVE

    @property
    def keys_dir(self) -> Path:
        return self.root / "keys"

    @property
    def blobs(self) -> Path:
        return self.root / "blobs"

    @property
    def dump_dir(self) -> Path:
        return self.root / "index" / "db"

    @property
    def latest_dump(self) -> Path:
        return self.dump_dir / "LATEST"

    @property
    def audit_dir(self) -> Path:
        return self.root / "audit"

    @property
    def journal_dir(self) -> Path:
        return self.root / "journal"

    @property
    def tmp(self) -> Path:
        return self.root / "tmp"

    @property
    def trash(self) -> Path:
        return self.root / "trash"

    @property
    def lock(self) -> Path:
        return self.root / LOCK_NAME

    def blob(self, address: str) -> Path:
        """``blobs/<hex[0:2]>/<hex[2:4]>/<hex>.blob``."""
        if len(address) != 64 or any(ch not in "0123456789abcdef" for ch in address):
            raise DocVaultError(
                "BLOB_INVALID", detail="A blob address must be 64 lower-case hex characters."
            )
        return self.blobs / address[:2] / address[2:4] / f"{address}.blob"

    def relative(self, path: Path) -> str:
        """Convert an absolute vault path to the relative form stored in the DB."""
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError as exc:
            raise DocVaultError("VAULT_INVALID", detail=f"{path} is outside the vault.") from exc


@dataclass(frozen=True, slots=True)
class ProbeReport:
    """What the filesystem probe found, for ``doctor`` and ``init`` output."""

    root: Path
    filesystem: str
    case_insensitive: bool


def vault_paths(root: Path) -> VaultPaths:
    if not root.is_absolute():
        raise DocVaultError("VAULT_INVALID", detail="The vault root must be absolute.")
    return VaultPaths(root=root)


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def _mount_table_linux() -> list[tuple[str, str]]:
    """Return ``(mountpoint, fstype)`` pairs from the kernel mount table."""
    entries: list[tuple[str, str]] = []
    try:
        with Path("/proc/self/mounts").open(encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mountpoint = parts[1].replace("\\040", " ").replace("\\011", "\t")
                entries.append((mountpoint, parts[2].lower()))
    except OSError:
        return []
    return entries


def filesystem_type(path: Path) -> str:
    """Best-effort filesystem type for the probe and diagnostics."""
    if _is_windows():  # pragma: no cover - exercised on Windows
        if str(path).startswith("\\\\"):
            return "unc"
        drive = path.drive
        root = f"{drive}\\" if drive else None
        if root is None:
            return "unknown"
        kind = ctypes.windll.kernel32.GetDriveTypeW(root)  # type: ignore[attr-defined]
        return {2: "removable", 3: "local", 4: "network", 5: "cdrom"}.get(kind, "unknown")

    resolved = path.resolve()
    best_mount = ""
    best_type = "unknown"
    for mountpoint, fstype in _mount_table_linux():
        prefix = mountpoint.rstrip("/") or "/"
        if (resolved == Path(prefix) or Path(prefix) in resolved.parents) and len(prefix) >= len(
            best_mount
        ):
            best_mount = prefix
            best_type = fstype
    return best_type


def _check_not_symlink(root: Path) -> None:
    """Reject a root that is, or is reached through, a symlink."""
    current = root
    while True:
        if current.is_symlink():
            raise DocVaultError(
                "FS_SYMLINK",
                detail=f"{current} is a symlink.",
            )
        if current.parent == current:
            return
        current = current.parent


def _check_network(root: Path) -> str:
    fstype = filesystem_type(root)
    if fstype == "unc" or fstype in NETWORK_FILESYSTEMS:
        raise DocVaultError(
            "FS_NETWORK_PATH",
            detail=f"The vault is on a {fstype} filesystem.",
        )
    return fstype


def _fsync_dir(path: Path) -> None:
    """Flush a directory entry. Windows has no equivalent; FlushFileBuffers covers files."""
    if _is_windows():  # pragma: no cover - exercised on Windows
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _probe_atomic_rename(root: Path) -> None:
    probe_dir = root / "tmp"
    token = secrets.token_hex(8)
    source = probe_dir / f".probe-{token}"
    target = probe_dir / f".probe-{token}.renamed"
    try:
        descriptor = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(b"docvault-atomic-probe")
            handle.flush()
            os.fsync(handle.fileno())
        source.replace(target)
        _fsync_dir(probe_dir)
        if target.read_bytes() != b"docvault-atomic-probe":
            raise OSError("rename probe read back different content")
    except OSError as exc:
        raise DocVaultError(
            "FS_NO_ATOMIC_RENAME",
            detail=f"Atomic rename or fsync failed under {probe_dir}: {exc}",
        ) from exc
    finally:
        with contextlib.suppress(OSError):
            source.unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            target.unlink(missing_ok=True)


def _probe_fsync(root: Path) -> None:
    probe = root / "tmp" / f".fsync-{secrets.token_hex(8)}"
    try:
        descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(b"docvault-fsync-probe")
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_dir(probe.parent)
    except OSError as exc:
        raise DocVaultError(
            "FS_NO_FSYNC",
            detail=f"fsync failed under {root}: {exc}",
        ) from exc
    finally:
        with contextlib.suppress(OSError):
            probe.unlink(missing_ok=True)


def _probe_casing(root: Path) -> bool:
    """Confirm case folding, if present, is consistent.

    NTFS and APFS fold case; ext4 does not. Both are safe for our lower-case
    hex names. What is unsafe is a filesystem where the folded name resolves
    to different content.
    """
    token = secrets.token_hex(8)
    lower = root / "tmp" / f".case-{token}"
    upper = root / "tmp" / f".CASE-{token.upper()}"
    lower.write_bytes(b"lower")
    try:
        try:
            descriptor = os.open(upper, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            case_insensitive = True
            if upper.read_bytes() != b"lower":
                raise DocVaultError(
                    "FS_UNRELIABLE_CASING",
                    detail="The case-folded name resolves to different content.",
                ) from None
        else:
            case_insensitive = False
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(b"upper")
            if lower.read_bytes() != b"lower" or upper.read_bytes() != b"upper":
                raise DocVaultError(
                    "FS_UNRELIABLE_CASING",
                    detail="Two names that differ only by case are not independent.",
                )
        return case_insensitive
    finally:
        for path in {lower, upper}:
            with contextlib.suppress(OSError):
                path.unlink(missing_ok=True)
        _fsync_dir(root / "tmp")


def ensure_layout(paths: VaultPaths) -> None:
    """Create the fixed folder set with private permissions."""
    for relative in REQUIRED_DIRS:
        directory = paths.root / relative
        directory.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            directory.chmod(0o700)
    if os.name == "posix":
        paths.root.chmod(0o700)


def probe_root(root: Path, *, create: bool = True) -> ProbeReport:
    """Run every filesystem check before the vault is created or opened.

    ``init`` passes ``create=True`` so a fresh path can be checked. ``doctor``
    passes ``create=False`` and never mutates an existing vault.
    """
    if not root.is_absolute():
        raise DocVaultError("VAULT_INVALID", detail="The vault root must be absolute.")
    _check_not_symlink(root)
    if not create and not root.is_dir():
        raise DocVaultError("VAULT_NOT_FOUND", detail=f"No vault directory at {root}.")
    try:
        root.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            root.chmod(0o700)
    except OSError as exc:
        raise DocVaultError("VAULT_UNWRITABLE", detail=f"Cannot create {root}: {exc}") from exc

    fstype = _check_network(root)
    paths = vault_paths(root)
    if create:
        ensure_layout(paths)
    else:
        missing = [relative for relative in REQUIRED_DIRS if not (root / relative).is_dir()]
        if missing:
            raise DocVaultError(
                "VAULT_MANIFEST_INVALID",
                detail=f"The vault is missing folders: {', '.join(missing)}.",
            )
    _probe_atomic_rename(root)
    _probe_fsync(root)
    case_insensitive = _probe_casing(root)
    return ProbeReport(root=root, filesystem=fstype, case_insensitive=case_insensitive)


def atomic_write(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Write a file, fsync it, rename it into place, then fsync the folder."""
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / f".{path.name}.{secrets.token_hex(8)}.part"
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        _fsync_dir(directory)
    except OSError as exc:
        with contextlib.suppress(OSError):
            temporary.unlink(missing_ok=True)
        raise DocVaultError("VAULT_UNWRITABLE", detail=f"Cannot write {path}: {exc}") from exc


def read_private_file(path: Path, *, expected_size: int | None = None) -> bytes:
    """Read a file and enforce an optional exact length."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise DocVaultError("VAULT_NOT_FOUND", detail=f"Cannot read {path}: {exc}") from exc
    if expected_size is not None and len(data) != expected_size:
        raise DocVaultError(
            "VAULT_MANIFEST_INVALID",
            detail=f"{path.name} must be exactly {expected_size} bytes, found {len(data)}.",
        )
    return data


def remove_stale_parts(paths: VaultPaths, *, older_than_seconds: int = 24 * 60 * 60) -> int:
    """Delete ``tmp/*.part`` older than the cutoff. Returns the count."""
    cutoff = time.time() - older_than_seconds
    removed = 0
    for candidate in paths.tmp.glob("*.part"):
        try:
            if candidate.stat().st_mtime < cutoff:
                candidate.unlink()
                removed += 1
        except OSError:
            continue
    return removed
