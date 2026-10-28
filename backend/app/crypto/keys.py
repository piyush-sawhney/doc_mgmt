"""Key hierarchy, key wrapping, column encryption, and blind indexes.

Everything here follows ``docs/05-crypto.md``. Labels and AAD strings are a
compatibility contract: changing one makes every existing vault unreadable, so
they live in this module as named constants and are covered by tests.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import unicodedata
from dataclasses import dataclass, field

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.errors import DocVaultError

# HKDF labels (docs/05 §3).
LABEL_FILE = "docvault/v1/file"
LABEL_META = "docvault/v1/meta"
LABEL_BIDX = "docvault/v1/bidx"
LABEL_ADDR = "docvault/v1/addr"
LABEL_MANIFEST = "docvault/v1/manifest"
LABEL_DUMP = "docvault/v1/dump"
LABEL_FP = "docvault/v1/fp"

# Associated data (docs/05 §4, docs/03 §5-6).
AAD_KEK = b"docvault/kek/v1"
AAD_FILE_KEY = b"docvault/filekey/v1"
AAD_BLOB = b"docvault/blob/v1"
AAD_BLOB_ADDR = b"docvault/blobaddr/v1"

VMK_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
KEY_ID_LEN = 8
FINGERPRINT_HEX_LEN = 32

ARGON2_M_COST = 65_536
ARGON2_T_COST = 3
ARGON2_P_COST = 1

DVK1_MAGIC = b"DVK1"
DVK1_VERSION = 1
DVK1_SIZE = 96
_DVK1 = struct.Struct("<4sB3s16sIII12s32s16s")

# Bound untrusted KDF parameters before handing them to Argon2. Without this a
# tampered key file could ask for terabytes of memory at start-up.
_MIN_M_COST = 8 * 1024
_MAX_M_COST = 1024 * 1024
_MIN_T_COST = 1
_MAX_T_COST = 10
_MIN_P_COST = 1
_MAX_P_COST = 8

COLUMN_VERSION = 0x01


@dataclass(frozen=True, slots=True)
class VaultKeys:
    """The in-memory key set derived from one vault master key."""

    vmk: bytes = field(repr=False)
    file_kek: bytes = field(repr=False)
    meta_key: bytes = field(repr=False)
    bidx_key: bytes = field(repr=False)
    addr_key: bytes = field(repr=False)
    manifest_key: bytes = field(repr=False)
    dump_key: bytes = field(repr=False)
    fingerprint: str

    @property
    def key_id(self) -> bytes:
        """First eight bytes of the 16-byte fingerprint digest.

        The manifest prints the digest as 32 hex characters; the blob header
        stores the first eight *digest* bytes, i.e. the first 16 hex
        characters. This keeps the header binary and lets a reader compare it
        without parsing text.
        """
        return bytes.fromhex(self.fingerprint)[:KEY_ID_LEN]


def hkdf(vmk: bytes, label: str, length: int = 32) -> bytes:
    """HKDF-SHA256 with an empty salt and the exact purpose label."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=label.encode("ascii"),
    ).derive(vmk)


def new_vmk() -> bytes:
    """A fresh 256-bit vault master key."""
    return secrets.token_bytes(VMK_LEN)


def derive_keys(vmk: bytes) -> VaultKeys:
    """Derive every sub-key and the public fingerprint from the VMK."""
    if len(vmk) != VMK_LEN:
        raise DocVaultError("CONFIG_INVALID", detail="A vault key must be 32 bytes.")
    fingerprint_digest = hashlib.sha256(hkdf(vmk, LABEL_FP)).hexdigest()
    return VaultKeys(
        vmk=vmk,
        file_kek=hkdf(vmk, LABEL_FILE),
        meta_key=hkdf(vmk, LABEL_META),
        bidx_key=hkdf(vmk, LABEL_BIDX),
        addr_key=hkdf(vmk, LABEL_ADDR),
        manifest_key=hkdf(vmk, LABEL_MANIFEST),
        dump_key=hkdf(vmk, LABEL_DUMP),
        fingerprint=fingerprint_digest[:FINGERPRINT_HEX_LEN],
    )


def _passphrase_bytes(passphrase: str) -> bytes:
    # NFC keeps a passphrase typed on two keyboards identical. It does not
    # weaken it; it removes a class of support calls.
    return unicodedata.normalize("NFC", passphrase).encode("utf-8")


def derive_passphrase_key(
    passphrase: str,
    salt: bytes,
    *,
    m_cost: int = ARGON2_M_COST,
    t_cost: int = ARGON2_T_COST,
    p_cost: int = ARGON2_P_COST,
) -> bytes:
    """Argon2id with the parameters recorded in the key file."""
    return hash_secret_raw(
        secret=_passphrase_bytes(passphrase),
        salt=salt,
        time_cost=t_cost,
        memory_cost=m_cost,
        parallelism=p_cost,
        hash_len=VMK_LEN,
        type=Type.ID,
    )


def wrap_vmk(
    vmk: bytes,
    passphrase: str,
    *,
    m_cost: int = ARGON2_M_COST,
    t_cost: int = ARGON2_T_COST,
    p_cost: int = ARGON2_P_COST,
) -> bytes:
    """Wrap the VMK under a passphrase and return exactly 96 ``DVK1`` bytes."""
    if len(vmk) != VMK_LEN:
        raise DocVaultError("CONFIG_INVALID", detail="A vault key must be 32 bytes.")
    if not (_MIN_M_COST <= m_cost <= _MAX_M_COST):
        raise DocVaultError("CONFIG_INVALID", detail="Argon2id m_cost is outside the safe range.")
    if not (_MIN_T_COST <= t_cost <= _MAX_T_COST):
        raise DocVaultError("CONFIG_INVALID", detail="Argon2id t_cost is outside the safe range.")
    if not (_MIN_P_COST <= p_cost <= _MAX_P_COST):
        raise DocVaultError("CONFIG_INVALID", detail="Argon2id p_cost is outside the safe range.")

    salt = secrets.token_bytes(SALT_LEN)
    key = derive_passphrase_key(passphrase, salt, m_cost=m_cost, t_cost=t_cost, p_cost=p_cost)
    nonce = secrets.token_bytes(NONCE_LEN)
    sealed = AESGCM(key).encrypt(nonce, vmk, AAD_KEK)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    packed = _DVK1.pack(
        DVK1_MAGIC,
        DVK1_VERSION,
        b"\x00" * 3,
        salt,
        m_cost,
        t_cost,
        p_cost,
        nonce,
        ciphertext,
        tag,
    )
    if len(packed) != DVK1_SIZE:  # pragma: no cover - a struct change would fail here
        raise DocVaultError("CONFIG_INVALID", detail="The DVK1 header is not 96 bytes.")
    return packed


def unwrap_vmk(wrapped: bytes, passphrase: str) -> bytes:
    """Unwrap a ``DVK1`` key file.

    A wrong passphrase and a damaged key file deliberately produce the same
    error. Structural damage is still checked first so a malformed file cannot
    drive a huge Argon2 allocation.
    """
    if len(wrapped) != DVK1_SIZE:
        raise DocVaultError("BAD_PASSPHRASE", detail="The key file is not 96 bytes.")
    magic, version, reserved, salt, m_cost, t_cost, p_cost, nonce, ciphertext, tag = _DVK1.unpack(
        wrapped
    )
    if magic != DVK1_MAGIC or version != DVK1_VERSION or reserved != b"\x00" * 3:
        raise DocVaultError("BAD_PASSPHRASE", detail="The key file header is not recognised.")
    if not (
        _MIN_M_COST <= m_cost <= _MAX_M_COST
        and _MIN_T_COST <= t_cost <= _MAX_T_COST
        and _MIN_P_COST <= p_cost <= _MAX_P_COST
    ):
        raise DocVaultError("BAD_PASSPHRASE", detail="The key file parameters are not accepted.")
    key = derive_passphrase_key(passphrase, salt, m_cost=m_cost, t_cost=t_cost, p_cost=p_cost)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext + tag, AAD_KEK)
    except InvalidTag as exc:
        raise DocVaultError(
            "BAD_PASSPHRASE",
            detail="Incorrect passphrase or damaged key file.",
        ) from exc


def encrypt_aead(key: bytes, plaintext: bytes, aad: bytes, *, nonce: bytes | None = None) -> bytes:
    """AES-256-GCM with a random nonce; returns ``nonce || ciphertext || tag``."""
    chosen = nonce or secrets.token_bytes(NONCE_LEN)
    return chosen + AESGCM(key).encrypt(chosen, plaintext, aad)


def decrypt_aead(key: bytes, sealed: bytes, aad: bytes) -> bytes:
    """Inverse of :func:`encrypt_aead`."""
    if len(sealed) < NONCE_LEN + 16:
        raise DocVaultError("BLOB_TAMPERED", detail="Ciphertext is too short.")
    nonce, body = sealed[:NONCE_LEN], sealed[NONCE_LEN:]
    try:
        return AESGCM(key).decrypt(nonce, body, aad)
    except InvalidTag as exc:
        raise DocVaultError("BLOB_TAMPERED", detail="Authentication failed.") from exc


def column_aad(table: str, column: str) -> bytes:
    """Bind a column ciphertext to its exact table and column."""
    return f"{table}.{column}".encode()


def encrypt_column(meta_key: bytes, table: str, column: str, plaintext: str | None) -> bytes | None:
    """Encrypt one database column value as ``0x01 || nonce || ciphertext || tag``."""
    if plaintext is None:
        return None
    return COLUMN_VERSION.to_bytes(1, "big") + encrypt_aead(
        meta_key, plaintext.encode("utf-8"), column_aad(table, column)
    )


def decrypt_column(
    meta_key: bytes, table: str, column: str, ciphertext: bytes | None
) -> str | None:
    """Decrypt one database column value."""
    if ciphertext is None:
        return None
    if not ciphertext or ciphertext[0] != COLUMN_VERSION:
        raise DocVaultError("COLUMN_TAMPERED", detail="Unknown column ciphertext version.")
    try:
        plaintext = decrypt_aead(meta_key, ciphertext[1:], column_aad(table, column))
    except DocVaultError as exc:
        # A column is not a blob; report the failure in the caller's terms so
        # the API can name the field instead of a file.
        raise DocVaultError(
            "COLUMN_TAMPERED",
            detail=f"{table}.{column} did not authenticate.",
        ) from exc
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DocVaultError("COLUMN_TAMPERED", detail="Column plaintext is not UTF-8.") from exc


def normalize_identifier(value: str) -> str:
    """Upper-case and strip spaces, hyphens, and dots (docs/05 §6)."""
    return "".join(ch for ch in value.upper() if ch not in {" ", "-", "."})


def blind_index(bidx_key: bytes, id_type: str, value: str) -> bytes:
    """Equality-only prefix-free blind index."""
    payload = f"v1|{id_type}|{normalize_identifier(value)}".encode()
    return COLUMN_VERSION.to_bytes(1, "big") + hmac.new(bidx_key, payload, hashlib.sha256).digest()


def blob_address(addr_key: bytes, salt: bytes, plaintext: bytes) -> str:
    """Hex content address: HMAC(addr_key, label || salt || plaintext)."""
    digest = hmac.new(addr_key, AAD_BLOB_ADDR + salt + plaintext, hashlib.sha256).digest()
    return digest.hex()


def blob_address_hmac(addr_key: bytes, salt: bytes) -> hmac.HMAC:
    """A streaming HMAC pre-loaded with the label and per-version salt."""
    return hmac.new(addr_key, AAD_BLOB_ADDR + salt, hashlib.sha256)
