"""Append-only, hash-chained audit files.

The JSONL files are the authority for integrity; the database keeps a query
index. Each entry's hash covers the previous hash and the canonical entry, so
removing or editing a line in the middle is detectable. The newest line can
still be truncated, which is the documented limit (R-6).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from app.core.errors import DocVaultError
from app.core.time import format_millis, now_utc
from app.crypto.canonical import canonical_json

ZERO_HASH = "0" * 64
TAIL_BYTES = 16 * 1024


@dataclass(frozen=True, slots=True)
class AuditCheck:
    """Result of walking the chain."""

    ok: bool
    entries: int
    first_bad_seq: int | None = None
    detail: str = ""


def _month_name(moment: datetime) -> str:
    return f"{moment:%Y-%m}.jsonl"


def _audit_files(directory: Path) -> list[Path]:
    return sorted(path for path in directory.glob("*.jsonl") if path.name != "anchors.jsonl")


def _read_last_entry(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            if size == 0:
                return None
            handle.seek(max(0, size - TAIL_BYTES))
            tail = handle.read().decode("utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as exc:
        raise DocVaultError(
            "AUDIT_CHAIN_BROKEN",
            detail=f"The tail of {path.name} cannot be read.",
        ) from exc
    for line in reversed(tail.splitlines()):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            raise DocVaultError(
                "AUDIT_CHAIN_BROKEN",
                detail=f"{path.name} ends with a partial or unreadable entry.",
            ) from exc
        if not isinstance(parsed, dict):
            raise DocVaultError(
                "AUDIT_CHAIN_BROKEN",
                detail=f"{path.name} ends with an entry that is not an object.",
            )
        return parsed
    return None


def _last_known_entry(paths_dir: Path, before: datetime) -> dict[str, Any] | None:
    """Find the newest entry at or before the target month.

    A corrupt tail is fatal here. Falling back to an older month would restart
    the chain with a duplicate sequence number and hide the damage.
    """
    candidates = [path for path in _audit_files(paths_dir) if path.name <= _month_name(before)]
    for path in reversed(candidates):
        entry = _read_last_entry(path)
        if entry is not None:
            if not isinstance(entry.get("seq"), int) or not isinstance(entry.get("hash"), str):
                raise DocVaultError(
                    "AUDIT_CHAIN_BROKEN",
                    detail=f"{path.name} has no usable seq and hash.",
                )
            return entry
    return None


def entry_hash(prev_hash: str, entry_without_hash: dict[str, Any]) -> str:
    """``sha256(prev_hash_hex || canonical_json(entry_without_hash))``."""
    payload = prev_hash.encode("ascii") + canonical_json(entry_without_hash)
    return hashlib.sha256(payload).hexdigest()


def append_event(
    audit_dir: Path,
    *,
    action: str,
    actor_id: str | None = None,
    object_type: str | None = None,
    object_id: str | None = None,
    outcome: str = "allow",
    source_ip: str | None = None,
    detail: dict[str, Any] | None = None,
    moment: datetime | None = None,
) -> dict[str, Any]:
    """Append one event, chaining from the previous month when needed."""
    moment = moment or now_utc()
    audit_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        with contextlib.suppress(OSError):
            audit_dir.chmod(0o700)
    target = audit_dir / _month_name(moment)
    previous = _last_known_entry(audit_dir, moment)
    if previous is None:
        sequence = 1
        prev_hash = ZERO_HASH
    else:
        sequence = int(previous["seq"]) + 1
        prev_hash = str(previous["hash"])
    entry: dict[str, Any] = {
        "seq": sequence,
        "ts": format_millis(moment),
        "actor_id": actor_id,
        "action": action,
        "object_type": object_type,
        "object_id": object_id,
        "outcome": outcome,
        "source_ip": source_ip,
        "detail": detail or {},
        "prev_hash": prev_hash,
    }
    entry["hash"] = entry_hash(prev_hash, entry)
    line = json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n"
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    descriptor = os.open(target, flags, 0o600)
    try:
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise OSError(f"Cannot append to the audit log {target}: {exc}") from exc
    return entry


def verify_chain(audit_dir: Path) -> AuditCheck:
    """Walk every monthly file and report the first broken entry."""
    expected_prev = ZERO_HASH
    expected_seq = 1
    entries = 0
    for path in _audit_files(audit_dir):
        try:
            handle = path.open("r", encoding="utf-8")
        except OSError as exc:
            return AuditCheck(False, entries, None, f"Cannot read {path.name}: {exc}")
        with handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return AuditCheck(
                        False, entries, expected_seq, f"{path.name}:{number} is not JSON"
                    )
                if not isinstance(entry, dict):
                    return AuditCheck(
                        False, entries, expected_seq, f"{path.name}:{number} is not an object"
                    )
                sequence = int(entry.get("seq", -1))
                if sequence != expected_seq:
                    return AuditCheck(
                        False,
                        entries,
                        sequence,
                        f"{path.name}:{number} has seq {sequence}, expected {expected_seq}",
                    )
                if entry.get("prev_hash") != expected_prev:
                    return AuditCheck(
                        False,
                        entries,
                        sequence,
                        f"{path.name}:{number} does not chain to the previous entry",
                    )
                recomputed = entry_hash(
                    expected_prev, {k: v for k, v in entry.items() if k != "hash"}
                )
                if entry.get("hash") != recomputed:
                    return AuditCheck(
                        False,
                        entries,
                        sequence,
                        f"{path.name}:{number} hash does not match its contents",
                    )
                expected_prev = recomputed
                expected_seq += 1
                entries += 1
    return AuditCheck(True, entries)


def month_for(moment: datetime) -> str:
    """The audit file name for a moment, exposed for tests and diagnostics."""
    return _month_name(moment)
