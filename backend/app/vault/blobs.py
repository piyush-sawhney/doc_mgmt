"""The ``DVC1`` blob container.

A blob is self-describing: its header wraps a per-blob file key under the
vault's ``file_kek``, and the payload is padded and encrypted under that file
key. Nothing here writes plaintext to disk. The address is computed over the
plaintext, so it doubles as an integrity check.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.errors import DocVaultError
from app.crypto.keys import (
    AAD_BLOB,
    AAD_FILE_KEY,
    NONCE_LEN,
    SALT_LEN,
    VaultKeys,
    blob_address,
    blob_address_hmac,
)

MAGIC: Final = b"DVC1"
FORMAT_VERSION: Final = 1
HEADER_SIZE: Final = 96
TAG_SIZE: Final = 16
WRAP_SIZE: Final = 48
FLAG_PADDED: Final = 0x01
DEFAULT_PAD_TO: Final = 4096
MAX_PAD_TO: Final = 1024 * 1024
CHUNK_SIZE: Final = 1024 * 1024

_HEADER = struct.Struct("<4sBB2s8sQ12s48s12s")


@dataclass(frozen=True, slots=True)
class BlobHeader:
    """Parsed 96-byte header, excluding the payload."""

    flags: int
    key_id: bytes
    plaintext_len: int
    nonce_wrap: bytes
    wrapped_fk: bytes
    nonce_payload: bytes

    @property
    def padded(self) -> bool:
        return bool(self.flags & FLAG_PADDED)


@dataclass(frozen=True, slots=True)
class EncryptedBlob:
    """A finished blob held in memory."""

    address: str
    salt: bytes
    data: bytes
    plaintext_len: int


@dataclass(frozen=True, slots=True)
class DecryptedBlob:
    """Verified plaintext and its identity."""

    address: str
    plaintext: bytes
    plaintext_len: int


def padded_length(plaintext_len: int, pad_to: int) -> int:
    """Round up to the next padding bucket; ``pad_to <= 0`` disables padding."""
    if pad_to < 0 or pad_to > MAX_PAD_TO:
        raise DocVaultError("BLOB_INVALID", detail="pad_to is outside the allowed range.")
    if pad_to == 0:
        return plaintext_len
    return ((plaintext_len + pad_to - 1) // pad_to) * pad_to


def _build_header(
    keys: VaultKeys,
    plaintext_len: int,
    pad_to: int,
) -> tuple[bytes, bytes, bytes]:
    file_key = secrets.token_bytes(32)
    nonce_wrap = secrets.token_bytes(NONCE_LEN)
    nonce_payload = secrets.token_bytes(NONCE_LEN)
    wrapped_fk = AESGCM(keys.file_kek).encrypt(nonce_wrap, file_key, AAD_FILE_KEY)
    padded = padded_length(plaintext_len, pad_to) != plaintext_len
    flags = FLAG_PADDED if padded else 0
    header = _HEADER.pack(
        MAGIC,
        FORMAT_VERSION,
        flags,
        b"\x00" * 2,
        keys.key_id,
        plaintext_len,
        nonce_wrap,
        wrapped_fk,
        nonce_payload,
    )
    if len(header) != HEADER_SIZE:  # pragma: no cover - a struct change would fail here
        raise DocVaultError("BLOB_INVALID", detail="The DVC1 header is not 96 bytes.")
    return header, file_key, nonce_payload


def parse_header(data: bytes | memoryview) -> BlobHeader:
    """Parse and validate a header without touching the payload."""
    view = memoryview(data)
    if len(view) < HEADER_SIZE + TAG_SIZE:
        raise DocVaultError("BLOB_INVALID", detail="Blob is shorter than a header and tag.")
    (
        magic,
        version,
        flags,
        reserved,
        key_id,
        plaintext_len,
        nonce_wrap,
        wrapped_fk,
        nonce_payload,
    ) = _HEADER.unpack_from(view)
    if magic != MAGIC:
        raise DocVaultError("BLOB_INVALID", detail="Wrong magic bytes.")
    if version != FORMAT_VERSION:
        raise DocVaultError("BLOB_INVALID", detail=f"Unsupported blob version {version}.")
    if flags & ~FLAG_PADDED:
        raise DocVaultError("BLOB_INVALID", detail="Unknown flags are set.")
    if reserved != b"\x00" * 2:
        raise DocVaultError("BLOB_INVALID", detail="Reserved header bytes are not zero.")
    if len(wrapped_fk) != WRAP_SIZE:
        raise DocVaultError("BLOB_INVALID", detail="The wrapped file key has the wrong size.")
    return BlobHeader(
        flags=flags,
        key_id=key_id,
        plaintext_len=plaintext_len,
        nonce_wrap=nonce_wrap,
        wrapped_fk=wrapped_fk,
        nonce_payload=nonce_payload,
    )


def _open_file_key(header: BlobHeader, keys: VaultKeys) -> bytes:
    if not hmac.compare_digest(header.key_id, keys.key_id):
        raise DocVaultError("BLOB_KEY_MISMATCH", detail="The blob key identifier differs.")
    try:
        return AESGCM(keys.file_kek).decrypt(header.nonce_wrap, header.wrapped_fk, AAD_FILE_KEY)
    except InvalidTag as exc:
        raise DocVaultError("BLOB_TAMPERED", detail="The file key did not authenticate.") from exc


def encrypt_blob(
    plaintext: bytes,
    keys: VaultKeys,
    *,
    salt: bytes | None = None,
    pad_to: int = DEFAULT_PAD_TO,
) -> EncryptedBlob:
    """Encrypt one payload into a complete ``DVC1`` byte string."""
    chosen_salt = salt if salt is not None else secrets.token_bytes(SALT_LEN)
    if len(chosen_salt) != SALT_LEN:
        raise DocVaultError("BLOB_INVALID", detail="The address salt must be 16 bytes.")
    header, file_key, nonce_payload = _build_header(keys, len(plaintext), pad_to)
    padded_len = padded_length(len(plaintext), pad_to)
    body = plaintext + b"\x00" * (padded_len - len(plaintext))
    sealed = AESGCM(file_key).encrypt(nonce_payload, body, AAD_BLOB)
    address = blob_address(keys.addr_key, chosen_salt, plaintext)
    return EncryptedBlob(
        address=address,
        salt=chosen_salt,
        data=header + sealed,
        plaintext_len=len(plaintext),
    )


def decrypt_blob(
    data: bytes,
    keys: VaultKeys,
    *,
    salt: bytes | None = None,
    expected_address: str | None = None,
) -> DecryptedBlob:
    """Authenticate and decrypt one blob.

    ``expected_address`` and ``salt`` are supplied when reading from the vault:
    the address is recomputed over the plaintext and compared with the file
    name, as ``verify`` does.
    """
    header = parse_header(data)
    ciphertext_len = len(data) - HEADER_SIZE - TAG_SIZE
    if header.plaintext_len > ciphertext_len:
        raise DocVaultError("BLOB_INVALID", detail="Declared plaintext length exceeds the payload.")
    if not header.padded and header.plaintext_len != ciphertext_len:
        raise DocVaultError(
            "BLOB_INVALID", detail="Unpadded payload length disagrees with the header."
        )
    if header.padded and ciphertext_len == 0:
        raise DocVaultError("BLOB_INVALID", detail="A padded payload cannot be empty.")

    file_key = _open_file_key(header, keys)
    try:
        padded = AESGCM(file_key).decrypt(header.nonce_payload, data[HEADER_SIZE:], AAD_BLOB)
    except InvalidTag as exc:
        raise DocVaultError("BLOB_TAMPERED", detail="The payload did not authenticate.") from exc
    plaintext = padded[: header.plaintext_len]

    if expected_address is not None:
        if salt is None:
            raise DocVaultError(
                "BLOB_INVALID", detail="An address check requires the per-version salt."
            )
        actual = blob_address(keys.addr_key, salt, plaintext)
        if not hmac.compare_digest(actual, expected_address):
            raise DocVaultError(
                "BLOB_ADDRESS_MISMATCH",
                detail="The file name does not match the decrypted content.",
            )
        address = actual
    else:
        address = ""

    return DecryptedBlob(
        address=address,
        plaintext=plaintext,
        plaintext_len=header.plaintext_len,
    )


def write_blob(
    source: BinaryIO,
    destination: Path,
    *,
    plaintext_len: int,
    keys: VaultKeys,
    salt: bytes | None = None,
    pad_to: int = DEFAULT_PAD_TO,
) -> str:
    """Stream plaintext from ``source`` into a new ``DVC1`` file.

    The destination must not exist. The caller renames it into ``blobs/`` only
    after this returns and after fsyncing. The function writes ciphertext from
    the first byte; it never creates a plaintext temporary file.

    Returns:
        The hex content address.
    """
    chosen_salt = salt if salt is not None else secrets.token_bytes(SALT_LEN)
    if len(chosen_salt) != SALT_LEN:
        raise DocVaultError("BLOB_INVALID", detail="The address salt must be 16 bytes.")
    padded_len = padded_length(plaintext_len, pad_to)
    header, file_key, nonce_payload = _build_header(keys, plaintext_len, pad_to)
    mac = blob_address_hmac(keys.addr_key, chosen_salt)
    cipher = Cipher(algorithms.AES(file_key), modes.GCM(nonce_payload))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(AAD_BLOB)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(destination, flags, 0o600)
    written = 0
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(header)
            remaining = plaintext_len
            while remaining:
                chunk = source.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise DocVaultError(
                        "BLOB_INVALID",
                        detail="The source ended before the declared plaintext length.",
                    )
                remaining -= len(chunk)
                written += len(chunk)
                mac.update(chunk)
                handle.write(encryptor.update(chunk))
            if source.read(1):
                raise DocVaultError(
                    "BLOB_INVALID",
                    detail="The source is longer than the declared plaintext length.",
                )
            padding = padded_len - plaintext_len
            if padding:
                handle.write(encryptor.update(b"\x00" * padding))
            encryptor.finalize()
            handle.write(encryptor.tag)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        # A partial .part file is ciphertext, not plaintext, but it is useless.
        destination.unlink(missing_ok=True)
        raise
    if written != plaintext_len:  # pragma: no cover - guarded by the read loop
        raise DocVaultError("BLOB_INVALID", detail="Short write.")
    return mac.hexdigest()


def read_blob_file(path: Path) -> bytes:
    """Read a whole blob. Callers that need streaming can open it themselves."""
    try:
        return path.read_bytes()
    except OSError as exc:
        raise DocVaultError("BLOB_INVALID", detail=f"Cannot read blob {path.name}: {exc}") from exc


def blob_digest(path: Path) -> str:
    """SHA-256 of the encrypted file, used by ``verify`` and dumps."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()
