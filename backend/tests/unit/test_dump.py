"""The ``DVD1`` dump container.

These tests are the format contract: header layout, chunk order, the final flag,
and the promise that a damaged dump never yields partial plaintext.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

import pytest

from app.core.errors import DocVaultError
from app.vault import dump

KEY = bytes.fromhex("11" * 32)


def _encrypt(tmp_path: Path, plaintext: bytes, *, key: bytes = KEY) -> Path:
    source = tmp_path / "source.dump"
    source.write_bytes(plaintext)
    destination = tmp_path / f"dump-{secrets.token_hex(4)}.enc"
    with source.open("rb") as handle:
        dump.encrypt_stream(handle, destination, dump_key=key)
    return destination


def _decrypt(path: Path, *, key: bytes = KEY) -> bytes:
    destination = path.parent / f"plain-{secrets.token_hex(4)}.dump"
    with path.open("rb") as handle:
        dump.decrypt_stream(handle, destination, dump_key=key)
    return destination.read_bytes()


def _header(path: Path) -> bytes:
    return path.read_bytes()[: dump.HEADER_SIZE]


@pytest.mark.parametrize("size", [0, 1, 1024, dump.CHUNK_SIZE - 1, dump.CHUNK_SIZE])
def test_round_trip_at_chunk_boundaries(tmp_path: Path, size: int) -> None:
    plaintext = os.urandom(size)
    path = _encrypt(tmp_path, plaintext)
    assert path.read_bytes()[:4] == b"DVD1"
    assert _decrypt(path) == plaintext


def test_a_multi_chunk_dump_round_trips(tmp_path: Path) -> None:
    plaintext = os.urandom(dump.CHUNK_SIZE * 3 + 17)
    path = _encrypt(tmp_path, plaintext)
    assert path.stat().st_size > len(plaintext)
    assert _decrypt(path) == plaintext


def test_the_header_is_32_bytes_and_parses(tmp_path: Path) -> None:
    path = _encrypt(tmp_path, b"payload")
    header = dump.read_header(path)
    assert header.chunk_size == dump.CHUNK_SIZE
    assert len(header.nonce_prefix) == dump.NONCE_PREFIX_LEN
    assert len(header.raw) == dump.HEADER_SIZE


@pytest.mark.parametrize(
    ("offset", "value"),
    [
        (0, b"DVD2"),
        (4, b"\x02"),
        (5, b"\x01"),
    ],
)
def test_a_header_tamper_is_refused_before_any_chunk(
    tmp_path: Path, offset: int, value: bytes
) -> None:
    path = _encrypt(tmp_path, b"payload")
    data = bytearray(path.read_bytes())
    data[offset : offset + len(value)] = value
    path.write_bytes(data)
    with pytest.raises(DocVaultError) as excinfo:
        _decrypt(path)
    assert excinfo.value.code == "DUMP_INVALID"


def test_a_changed_nonce_prefix_fails_authentication(tmp_path: Path) -> None:
    path = _encrypt(tmp_path, os.urandom(dump.CHUNK_SIZE + 10))
    data = bytearray(path.read_bytes())
    data[12] ^= 0x01
    path.write_bytes(data)
    with pytest.raises(DocVaultError) as excinfo:
        _decrypt(path)
    assert excinfo.value.code == "DUMP_TAMPERED"


def test_a_flipped_ciphertext_byte_is_refused(tmp_path: Path) -> None:
    path = _encrypt(tmp_path, os.urandom(2048))
    data = bytearray(path.read_bytes())
    data[dump.HEADER_SIZE + 100] ^= 0x01
    path.write_bytes(data)
    with pytest.raises(DocVaultError) as excinfo:
        _decrypt(path)
    assert excinfo.value.code == "DUMP_TAMPERED"


def test_removing_the_final_chunk_is_reported_as_truncation(tmp_path: Path) -> None:
    plaintext = os.urandom(dump.CHUNK_SIZE + 100)
    path = _encrypt(tmp_path, plaintext)
    data = path.read_bytes()
    # Cut the whole last chunk: header, one full chunk, then the short final one.
    cut = dump.HEADER_SIZE + dump.CHUNK_SIZE + dump.TAG_SIZE
    path.write_bytes(data[:cut])
    with pytest.raises(DocVaultError) as excinfo:
        _decrypt(path)
    assert excinfo.value.code == "DUMP_TRUNCATED"


def test_cutting_inside_a_chunk_is_reported_as_truncation(tmp_path: Path) -> None:
    path = _encrypt(tmp_path, os.urandom(dump.CHUNK_SIZE * 2))
    data = path.read_bytes()
    path.write_bytes(data[:-1])
    with pytest.raises(DocVaultError) as excinfo:
        _decrypt(path)
    assert excinfo.value.code in {"DUMP_TRUNCATED", "DUMP_TAMPERED"}


def test_swapping_two_chunks_fails(tmp_path: Path) -> None:
    plaintext = os.urandom(dump.CHUNK_SIZE * 2 + 5)
    path = _encrypt(tmp_path, plaintext)
    data = bytearray(path.read_bytes())
    first = data[dump.HEADER_SIZE : dump.HEADER_SIZE + dump.READ_BLOCK]
    second = data[dump.HEADER_SIZE + dump.READ_BLOCK : dump.HEADER_SIZE + 2 * dump.READ_BLOCK]
    data[dump.HEADER_SIZE : dump.HEADER_SIZE + dump.READ_BLOCK] = second
    data[dump.HEADER_SIZE + dump.READ_BLOCK : dump.HEADER_SIZE + 2 * dump.READ_BLOCK] = first
    path.write_bytes(data)
    with pytest.raises(DocVaultError) as excinfo:
        _decrypt(path)
    assert excinfo.value.code == "DUMP_TAMPERED"


def test_appended_data_is_rejected(tmp_path: Path) -> None:
    path = _encrypt(tmp_path, b"payload")
    with path.open("ab") as handle:
        handle.write(b"extra")
    with pytest.raises(DocVaultError) as excinfo:
        _decrypt(path)
    assert excinfo.value.code == "DUMP_TAMPERED"


def test_a_wrong_key_is_refused_and_leaves_no_plaintext(tmp_path: Path) -> None:
    path = _encrypt(tmp_path, os.urandom(4096))
    destination = tmp_path / "restore.dump"
    with path.open("rb") as handle, pytest.raises(DocVaultError) as excinfo:
        dump.decrypt_stream(handle, destination, dump_key=bytes.fromhex("22" * 32))
    assert excinfo.value.code == "DUMP_TAMPERED"
    assert not destination.exists()


def test_a_truncated_dump_leaves_no_plaintext(tmp_path: Path) -> None:
    path = _encrypt(tmp_path, os.urandom(dump.CHUNK_SIZE + 1))
    path.write_bytes(path.read_bytes()[: dump.HEADER_SIZE + 10])
    destination = tmp_path / "restore.dump"
    with path.open("rb") as handle, pytest.raises(DocVaultError):
        dump.decrypt_stream(handle, destination, dump_key=KEY)
    assert not destination.exists()


def test_an_empty_file_is_not_a_dump(tmp_path: Path) -> None:
    path = tmp_path / "empty.enc"
    path.write_bytes(b"")
    with pytest.raises(DocVaultError) as excinfo:
        dump.read_header(path)
    assert excinfo.value.code == "DUMP_INVALID"


def test_a_missing_dump_is_named(tmp_path: Path) -> None:
    with pytest.raises(DocVaultError) as excinfo:
        dump.read_header(tmp_path / "absent.enc")
    assert excinfo.value.code == "DUMP_NOT_FOUND"


def test_file_sha256_matches_the_encrypted_bytes(tmp_path: Path) -> None:
    path = _encrypt(tmp_path, b"payload")
    assert dump.file_sha256(path) == hashlib.sha256(path.read_bytes()).hexdigest()
