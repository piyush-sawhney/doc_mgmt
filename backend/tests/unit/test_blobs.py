"""The DVC1 container: layout, padding, authentication, and streaming."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from app.core.errors import DocVaultError
from app.crypto.keys import VaultKeys, derive_keys
from app.vault.blobs import (
    HEADER_SIZE,
    TAG_SIZE,
    decrypt_blob,
    encrypt_blob,
    parse_header,
    write_blob,
    write_blob_stream,
)


def test_round_trip_and_padding(keys: VaultKeys) -> None:
    # Arrange
    plaintext = b"a small scanned page"

    # Act
    blob = encrypt_blob(plaintext, keys, pad_to=4096)
    opened = decrypt_blob(blob.data, keys, salt=blob.salt, expected_address=blob.address)

    # Assert
    assert opened.plaintext == plaintext
    assert len(blob.data) == HEADER_SIZE + 4096 + TAG_SIZE
    assert parse_header(blob.data).plaintext_len == len(plaintext)


def test_empty_plaintext_has_no_padding_flag(keys: VaultKeys) -> None:
    # Act
    blob = encrypt_blob(b"", keys, pad_to=4096)
    header = parse_header(blob.data)

    # Assert
    assert header.plaintext_len == 0
    assert header.padded is False
    assert len(blob.data) == HEADER_SIZE + TAG_SIZE
    assert decrypt_blob(blob.data, keys).plaintext == b""


def test_padding_can_be_disabled(keys: VaultKeys) -> None:
    # Act
    blob = encrypt_blob(b"exact", keys, pad_to=0)

    # Assert
    assert len(blob.data) == HEADER_SIZE + len(b"exact") + TAG_SIZE
    assert parse_header(blob.data).padded is False


def test_payload_tampering_is_rejected(keys: VaultKeys) -> None:
    # Arrange
    blob = bytearray(encrypt_blob(b"content", keys, pad_to=64).data)
    blob[HEADER_SIZE] ^= 0x01

    # Act / Assert
    with pytest.raises(DocVaultError) as caught:
        decrypt_blob(bytes(blob), keys)
    assert caught.value.code == "BLOB_TAMPERED"


def test_wrong_vault_key_is_rejected(keys: VaultKeys) -> None:
    # Arrange
    other = derive_keys(bytes([9]) * 32)
    blob = encrypt_blob(b"content", other, pad_to=64)

    # Act / Assert
    with pytest.raises(DocVaultError) as caught:
        decrypt_blob(blob.data, keys)
    assert caught.value.code == "BLOB_KEY_MISMATCH"


def test_address_mismatch_is_rejected(keys: VaultKeys) -> None:
    # Arrange
    blob = encrypt_blob(b"content", keys, pad_to=64)

    # Act / Assert
    with pytest.raises(DocVaultError) as caught:
        decrypt_blob(
            blob.data,
            keys,
            salt=blob.salt,
            expected_address="0" * 64,
        )
    assert caught.value.code == "BLOB_ADDRESS_MISMATCH"


def test_unknown_flags_are_rejected(keys: VaultKeys) -> None:
    # Arrange
    blob = bytearray(encrypt_blob(b"content", keys, pad_to=64).data)
    blob[5] = 0x04

    # Act / Assert
    with pytest.raises(DocVaultError) as caught:
        decrypt_blob(bytes(blob), keys)
    assert caught.value.code == "BLOB_INVALID"


def test_wrong_magic_is_rejected(keys: VaultKeys) -> None:
    # Arrange
    blob = bytearray(encrypt_blob(b"content", keys, pad_to=64).data)
    blob[0:4] = b"NOPE"

    # Act / Assert
    with pytest.raises(DocVaultError):
        decrypt_blob(bytes(blob), keys)


def test_streaming_writer_matches_memory_address(keys: VaultKeys, tmp_path: Path) -> None:
    # Arrange
    plaintext = b"x" * 9000
    salt = b"\x05" * 16
    destination = tmp_path / "blob.part"

    # Act
    address = write_blob(
        io.BytesIO(plaintext),
        destination,
        plaintext_len=len(plaintext),
        keys=keys,
        salt=salt,
        pad_to=4096,
    )
    opened = decrypt_blob(destination.read_bytes(), keys, salt=salt, expected_address=address)
    memory = encrypt_blob(plaintext, keys, salt=salt, pad_to=4096)

    # Assert
    assert opened.plaintext == plaintext
    assert address == memory.address
    assert destination.stat().st_size == HEADER_SIZE + 12288 + TAG_SIZE


def test_streaming_writer_rejects_short_source(keys: VaultKeys, tmp_path: Path) -> None:
    # Arrange
    destination = tmp_path / "short.part"

    # Act / Assert
    with pytest.raises(DocVaultError):
        write_blob(
            io.BytesIO(b"too short"),
            destination,
            plaintext_len=100,
            keys=keys,
        )
    assert not destination.exists()


def test_streaming_writer_rejects_long_source(keys: VaultKeys, tmp_path: Path) -> None:
    # Arrange
    destination = tmp_path / "long.part"

    # Act / Assert
    with pytest.raises(DocVaultError):
        write_blob(
            io.BytesIO(b"longer than declared"),
            destination,
            plaintext_len=4,
            keys=keys,
        )
    assert not destination.exists()


def test_unknown_length_streaming_writer_round_trips(keys: VaultKeys, tmp_path: Path) -> None:
    plaintext = b"streamed content" * 800
    salt = b"\x07" * 16
    destination = tmp_path / "unknown-length.part"

    address, length = write_blob_stream(
        io.BytesIO(plaintext),
        destination,
        max_plaintext_len=len(plaintext),
        keys=keys,
        salt=salt,
        pad_to=4096,
    )
    opened = decrypt_blob(
        destination.read_bytes(),
        keys,
        salt=salt,
        expected_address=address,
    )

    assert length == len(plaintext)
    assert opened.plaintext == plaintext


def test_unknown_length_streaming_writer_removes_oversized_partial(
    keys: VaultKeys, tmp_path: Path
) -> None:
    destination = tmp_path / "oversized.part"

    with pytest.raises(DocVaultError) as caught:
        write_blob_stream(
            io.BytesIO(b"too large"),
            destination,
            max_plaintext_len=4,
            keys=keys,
        )

    assert caught.value.code == "PAYLOAD_TOO_LARGE"
    assert not destination.exists()
