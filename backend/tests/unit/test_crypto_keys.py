"""Key hierarchy, wrapping, column encryption, and blind indexes."""

from __future__ import annotations

import pytest

from app.core.errors import DocVaultError
from app.crypto import keys as k
from app.crypto.keys import VaultKeys, derive_keys


def test_subkeys_are_deterministic_and_distinct() -> None:
    # Arrange
    vmk = bytes(range(32))

    # Act
    first = derive_keys(vmk)
    second = derive_keys(vmk)

    # Assert
    assert first == second
    assert len({first.file_kek, first.meta_key, first.bidx_key, first.addr_key}) == 4
    assert first.fingerprint == second.fingerprint
    assert len(first.fingerprint) == 32


def test_fingerprint_is_locked_for_a_known_vmk() -> None:
    # Arrange / Act
    fingerprint = derive_keys(bytes(32)).fingerprint

    # Assert: this is a regression lock. A change means existing manifests
    # would report VAULT_KEY_MISMATCH, so it needs a format-version bump.
    assert fingerprint == "3017f1f1716ac74687fc6db76d69d059"


def test_hkdf_labels_are_domain_separated() -> None:
    # Arrange
    vmk = bytes([7]) * 32

    # Act
    one = k.hkdf(vmk, k.LABEL_FILE)
    two = k.hkdf(vmk, k.LABEL_META)

    # Assert
    assert one != two
    assert len(one) == len(two) == 32


def test_vmk_wrap_round_trip() -> None:
    # Arrange
    vmk = bytes(range(32))

    # Act
    wrapped = k.wrap_vmk(vmk, "Stapler-Harbor-Cactus-42")
    unwrapped = k.unwrap_vmk(wrapped, "Stapler-Harbor-Cactus-42")

    # Assert
    assert len(wrapped) == 96
    assert wrapped[:4] == b"DVK1"
    assert unwrapped == vmk


def test_wrong_passphrase_is_rejected_without_detail() -> None:
    # Arrange
    wrapped = k.wrap_vmk(bytes(32), "Stapler-Harbor-Cactus-42")

    # Act / Assert
    with pytest.raises(DocVaultError) as caught:
        k.unwrap_vmk(wrapped, "Different-Harbor-Cactus-42")
    assert caught.value.code == "BAD_PASSPHRASE"


def test_tampered_dvk1_tag_is_rejected() -> None:
    # Arrange
    wrapped = bytearray(k.wrap_vmk(bytes(32), "Stapler-Harbor-Cactus-42"))
    wrapped[-1] ^= 0x01

    # Act / Assert
    with pytest.raises(DocVaultError):
        k.unwrap_vmk(bytes(wrapped), "Stapler-Harbor-Cactus-42")


def test_dvk1_rejects_absurd_argon2_cost() -> None:
    # Arrange
    wrapped = bytearray(k.wrap_vmk(bytes(32), "Stapler-Harbor-Cactus-42"))
    wrapped[24:28] = (2**31).to_bytes(4, "little")

    # Act / Assert
    with pytest.raises(DocVaultError):
        k.unwrap_vmk(bytes(wrapped), "Stapler-Harbor-Cactus-42")


def test_column_round_trip_and_aad_binding(keys: VaultKeys) -> None:
    # Arrange
    ciphertext = k.encrypt_column(keys.meta_key, "documents", "title", "Sale deed")

    # Act
    plaintext = k.decrypt_column(keys.meta_key, "documents", "title", ciphertext)

    # Assert
    assert plaintext == "Sale deed"
    assert ciphertext is not None
    assert ciphertext[0] == 1
    with pytest.raises(DocVaultError) as caught:
        k.decrypt_column(keys.meta_key, "entities", "title", ciphertext)
    assert caught.value.code == "COLUMN_TAMPERED"


def test_column_null_stays_null(keys: VaultKeys) -> None:
    assert k.encrypt_column(keys.meta_key, "documents", "issuer", None) is None
    assert k.decrypt_column(keys.meta_key, "documents", "issuer", None) is None


def test_blind_index_normalises_and_is_keyed(keys: VaultKeys) -> None:
    # Arrange / Act
    one = k.blind_index(keys.bidx_key, "pan", "abcde 1234-f")
    two = k.blind_index(keys.bidx_key, "pan", "ABCDE1234F")
    other = k.blind_index(keys.bidx_key, "passport", "ABCDE1234F")

    # Assert
    assert one == two
    assert one != other
    assert len(one) == 33
    assert one[0] == 1


def test_blob_address_is_salt_scoped(keys: VaultKeys) -> None:
    # Arrange
    salt_one = b"\x01" * 16
    salt_two = b"\x02" * 16

    # Act
    first = k.blob_address(keys.addr_key, salt_one, b"same bytes")
    second = k.blob_address(keys.addr_key, salt_two, b"same bytes")

    # Assert
    assert first != second
    assert len(first) == 64
    assert first == first.lower()
