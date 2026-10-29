"""The ``DVD1`` encrypted database-dump container.

A dump is a stream, not a document: it can be hundreds of megabytes and it never
needs random access. The container is therefore a 32-byte header followed by
fixed-size, independently authenticated chunks (``docs/03`` §9). The header is
inside every chunk's AAD, and each chunk's AAD carries its index and a final
flag, so a chunk cannot be reordered, duplicated, or dropped from the tail
without a tag failure.

Nothing here runs ``pg_dump``. This module only turns a byte stream into a dump
file and back; ``app/db/backup.py`` owns the subprocess and the pointer.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.errors import DocVaultError

MAGIC: Final = b"DVD1"
FORMAT_VERSION: Final = 1
HEADER_SIZE: Final = 32
CHUNK_SIZE: Final = 65536
TAG_SIZE: Final = 16
NONCE_PREFIX_LEN: Final = 8
READ_BLOCK: Final = CHUNK_SIZE + TAG_SIZE

_HEADER = struct.Struct("<4sBB2sI8s12s")


@dataclass(frozen=True, slots=True)
class DumpHeader:
    """The parsed 32-byte header. ``raw`` is what goes into every AAD."""

    chunk_size: int
    nonce_prefix: bytes = b""
    raw: bytes = b""


def _pack_header(chunk_size: int, nonce_prefix: bytes) -> bytes:
    raw = _HEADER.pack(
        MAGIC,
        FORMAT_VERSION,
        0,
        b"\x00" * 2,
        chunk_size,
        nonce_prefix,
        b"\x00" * 12,
    )
    if len(raw) != HEADER_SIZE:  # pragma: no cover - a struct change would fail here
        raise DocVaultError("DUMP_INVALID", detail="The DVD1 header is not 32 bytes.")
    return raw


def parse_header(data: bytes | memoryview) -> DumpHeader:
    """Parse and validate a header. Called before any chunk is decrypted."""
    view = memoryview(data)
    if len(view) < HEADER_SIZE:
        raise DocVaultError("DUMP_INVALID", detail="The dump is shorter than its header.")
    magic, version, flags, reserved, chunk_size, nonce_prefix, tail = _HEADER.unpack_from(view)
    if magic != MAGIC:
        raise DocVaultError("DUMP_INVALID", detail="Wrong magic bytes.")
    if version != FORMAT_VERSION:
        raise DocVaultError("DUMP_INVALID", detail=f"Unsupported dump version {version}.")
    if flags != 0:
        raise DocVaultError("DUMP_INVALID", detail="Unknown header flags are set.")
    if reserved != b"\x00" * 2 or tail != b"\x00" * 12:
        raise DocVaultError("DUMP_INVALID", detail="Reserved header bytes are not zero.")
    if chunk_size != CHUNK_SIZE:
        raise DocVaultError(
            "DUMP_INVALID",
            detail=f"Chunk size {chunk_size} is not the documented {CHUNK_SIZE}.",
        )
    return DumpHeader(
        chunk_size=chunk_size,
        nonce_prefix=nonce_prefix,
        raw=bytes(view[:HEADER_SIZE]),
    )


def read_header(path: Path) -> DumpHeader:
    """Read and validate just the header of a dump file."""
    try:
        with path.open("rb") as handle:
            data = handle.read(HEADER_SIZE)
    except OSError as exc:
        raise DocVaultError("DUMP_NOT_FOUND", detail=f"Cannot read {path.name}: {exc}") from exc
    return parse_header(data)


def _nonce(prefix: bytes, index: int) -> bytes:
    return prefix + index.to_bytes(4, "big")


def _aad(header: bytes, index: int, final: bool) -> bytes:
    return header + index.to_bytes(4, "big") + (b"\x01" if final else b"\x00")


def encrypt_stream(source: IO[bytes], destination: Path, *, dump_key: bytes) -> int:
    """Encrypt ``source`` into a new dump file and return the plaintext length.

    The destination must not exist. The caller renames it into ``index/db/``
    only after this returns, so a crash never leaves a half-written dump under
    a name that ``LATEST`` could name.
    """
    nonce_prefix = secrets.token_bytes(NONCE_PREFIX_LEN)
    header = _pack_header(CHUNK_SIZE, nonce_prefix)
    cipher = AESGCM(dump_key)
    plaintext_bytes = 0
    index = 0

    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(header)
            current = source.read(CHUNK_SIZE)
            while True:
                following = source.read(CHUNK_SIZE)
                final = not following
                sealed = cipher.encrypt(
                    _nonce(nonce_prefix, index),
                    current,
                    _aad(header, index, final),
                )
                handle.write(sealed)
                plaintext_bytes += len(current)
                index += 1
                if final:
                    break
                current = following
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        destination.unlink(missing_ok=True)
        if getattr(exc, "errno", None) == 28:
            raise DocVaultError(
                "STORAGE_FULL",
                detail="The dump could not be written: the disk is full.",
            ) from exc
        raise DocVaultError(
            "VAULT_UNWRITABLE", detail=f"Cannot write {destination}: {exc}"
        ) from exc
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return plaintext_bytes


def _decrypt_chunk(
    cipher: AESGCM,
    header: DumpHeader,
    index: int,
    chunk: bytes,
    *,
    final: bool,
) -> bytes:
    """Decrypt one chunk, naming truncation separately from tampering."""
    try:
        return cipher.decrypt(
            _nonce(header.nonce_prefix, index),
            chunk,
            _aad(header.raw, index, final),
        )
    except InvalidTag as exc:
        # A full chunk at EOF is either genuinely last or the file lost its
        # tail. If it authenticates as a non-final chunk, the tail was removed.
        if final and len(chunk) == READ_BLOCK:
            try:
                cipher.decrypt(
                    _nonce(header.nonce_prefix, index),
                    chunk,
                    _aad(header.raw, index, False),
                )
            except InvalidTag:
                pass
            else:
                raise DocVaultError(
                    "DUMP_TRUNCATED",
                    detail="The dump ended without its final chunk.",
                ) from exc
        raise DocVaultError(
            "DUMP_TAMPERED",
            detail="A chunk did not authenticate under this vault's dump key.",
        ) from exc


def decrypt_stream(source: IO[bytes], destination: Path, *, dump_key: bytes) -> int:
    """Decrypt a dump into ``destination`` and return the plaintext length.

    The whole file is authenticated chunk by chunk. The final flag is inside
    the AAD, so a dump whose tail was removed raises ``DUMP_TRUNCATED`` rather
    than restoring a prefix. The partial plaintext file is deleted on failure.
    """
    header = parse_header(source.read(HEADER_SIZE))
    cipher = AESGCM(dump_key)
    plaintext_bytes = 0
    index = 0
    pushback = b""

    def read_payload(limit: int) -> bytes:
        nonlocal pushback
        data = pushback[:limit]
        pushback = pushback[len(data) :]
        remaining = limit - len(data)
        if remaining:
            data += source.read(remaining)
        return data

    def peek() -> bytes:
        nonlocal pushback
        if pushback:
            byte, pushback = pushback[:1], pushback[1:]
            return byte
        return source.read(1)

    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            while True:
                chunk = read_payload(READ_BLOCK)
                if len(chunk) < TAG_SIZE:
                    raise DocVaultError(
                        "DUMP_TRUNCATED",
                        detail="The dump ended before its final authenticated chunk.",
                    )
                final = len(chunk) < READ_BLOCK
                if not final:
                    byte = peek()
                    if byte:
                        pushback = byte + pushback
                    else:
                        final = True
                plaintext = _decrypt_chunk(cipher, header, index, chunk, final=final)
                handle.write(plaintext)
                plaintext_bytes += len(plaintext)
                index += 1
                if final:
                    break
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return plaintext_bytes


def file_sha256(path: Path) -> str:
    """SHA-256 of an encrypted dump file, as recorded in ``LATEST``."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
