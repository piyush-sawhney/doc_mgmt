"""Where the application's database password lives.

It is never in ``docvault.toml``, the vault, an environment variable, or a log
line (docs/02 §6.3). On Windows it is sealed with machine-scope DPAPI. On
Linux — a development target — it goes in a ``0600`` file beside the
configuration, and a production install is refused because that fallback has
no service-account boundary (docs/08 §2.2).
"""

from __future__ import annotations

import ctypes
import json
import os
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import DocVaultError
from app.vault.layout import atomic_write

CREDENTIAL_NAME = "docvault-db.cred"
CREDENTIAL_FORMAT = 1
PROTECT_LOCAL_MACHINE = 0x4


@dataclass(frozen=True, slots=True)
class Credential:
    role: str
    password: str


def credential_path(config_path: Path) -> Path:
    """The credential sits beside the configuration, never inside the vault."""
    return config_path.parent / CREDENTIAL_NAME


def _using_dpapi() -> bool:
    return os.name == "nt"


def _serialise(credential: Credential) -> bytes:
    return json.dumps(
        {
            "format": CREDENTIAL_FORMAT,
            "role": credential.role,
            "password": credential.password,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _parse(data: bytes) -> Credential:
    try:
        payload = json.loads(data)
        if payload.get("format") != CREDENTIAL_FORMAT:
            raise ValueError("unknown credential format")
        role = payload["role"]
        password = payload["password"]
        if not isinstance(role, str) or not isinstance(password, str):
            raise ValueError("credential fields must be strings")
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise DocVaultError(
            "DB_CREDENTIAL_UNREADABLE",
            detail=f"The credential file is not a credential: {exc}",
        ) from exc
    return Credential(role=role, password=password)


def save_credential(path: Path, credential: Credential, *, environment: str) -> None:
    """Write the credential atomically with owner-only permissions."""
    if not _using_dpapi() and environment == "production":
        raise DocVaultError(
            "DB_CREDENTIAL_UNREADABLE",
            detail="A production database credential needs DPAPI (Windows).",
            remediation="Run the production install on Windows, or use development mode.",
        )
    plaintext = _serialise(credential)
    data = _dpapi_protect(plaintext) if _using_dpapi() else plaintext
    try:
        atomic_write(path, data)
    except DocVaultError as exc:
        raise DocVaultError(
            "CONFIG_INVALID",
            detail=f"Could not write the database credential: {exc.detail}",
            remediation="Check write access to the configuration folder.",
        ) from exc


def load_credential(path: Path) -> Credential:
    """Read the credential, mapping every failure to ``DB_CREDENTIAL_UNREADABLE``."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise DocVaultError(
            "DB_CREDENTIAL_UNREADABLE",
            detail=f"No database credential at {path}.",
            remediation="Run docvault init or docvault init --reuse-vault.",
        ) from exc
    if _using_dpapi():
        data = _dpapi_unprotect(data)
    return _parse(data)


# ---------------------------------------------------------------------------
# Windows DPAPI. Machine scope so the service account and an administrator
# running doctor in another session both decrypt the same value.
# ---------------------------------------------------------------------------


def _dpapi_protect(data: bytes) -> bytes:  # pragma: no cover - Windows only
    if not _using_dpapi():
        return data
    return _dpapi_call(data, protect=True)


def _dpapi_unprotect(data: bytes) -> bytes:  # pragma: no cover - Windows only
    if not _using_dpapi():
        return data
    try:
        return _dpapi_call(data, protect=False)
    except OSError as exc:
        raise DocVaultError(
            "DB_CREDENTIAL_UNREADABLE",
            detail=f"DPAPI could not unseal the credential: {exc}",
        ) from exc


def _dpapi_call(data: bytes, *, protect: bool) -> bytes:  # pragma: no cover - Windows only
    """Call ``CryptProtectData`` or ``CryptUnprotectData`` through ctypes."""

    class DataBlob(ctypes.Structure):
        _fields_ = [  # noqa: RUF012 - ctypes reads this exact name
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]

    buffer = ctypes.create_string_buffer(data, len(data))
    source = DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    result = DataBlob()

    if protect:
        function = crypt32.CryptProtectData
        function.argtypes = [
            ctypes.POINTER(DataBlob),
            wintypes.LPCWSTR,
            ctypes.POINTER(DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(DataBlob),
        ]
    else:
        function = crypt32.CryptUnprotectData
        function.argtypes = [
            ctypes.POINTER(DataBlob),
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(DataBlob),
        ]
    function.restype = wintypes.BOOL
    flags = PROTECT_LOCAL_MACHINE if protect else 0
    if protect:
        ok = function(
            ctypes.byref(source), "DocVault", None, None, None, flags, ctypes.byref(result)
        )
    else:
        description = wintypes.LPWSTR()
        ok = function(
            ctypes.byref(source),
            ctypes.byref(description),
            None,
            None,
            None,
            flags,
            ctypes.byref(result),
        )
    if not ok:
        raise OSError(kernel32.GetLastError(), "DPAPI call failed")
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        kernel32.LocalFree(result.pbData)
