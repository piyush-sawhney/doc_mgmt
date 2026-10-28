"""Manifest construction, signing, and unknown-field preservation."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.errors import DocVaultError
from app.crypto.canonical import canonical_json
from app.crypto.keys import VaultKeys, derive_keys
from app.vault import manifest


def _document(keys: VaultKeys) -> dict[str, object]:
    return manifest.build(
        vault_id="0192f0c4-7a1e-7c3b-9a55-2c1f0b6d4e11",
        display_name="Knaps - Records",
        created_at="2026-10-28T10:12:03Z",
        app_version="1.0.0",
        schema_version=1,
        key_fingerprint=keys.fingerprint,
        max_file_bytes=100 * 1024 * 1024,
    )


def test_canonical_json_is_sorted_and_compact() -> None:
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_sign_and_verify(keys: VaultKeys) -> None:
    # Arrange
    signed = manifest.sign(_document(keys), keys)

    # Act
    manifest.verify(signed, keys)
    parsed = manifest.validate_structure(signed)

    # Assert
    assert parsed.vault_id == "0192f0c4-7a1e-7c3b-9a55-2c1f0b6d4e11"
    assert parsed.pad_to == 4096
    assert parsed.fanout == (2, 2)


def test_unknown_fields_survive_signing_and_rewriting(keys: VaultKeys) -> None:
    # Arrange
    document = _document(keys)
    document["future_field"] = {"added_by": "a newer app"}
    signed = manifest.sign(document, keys)

    # Act
    updated = manifest.sign(manifest.Manifest(signed).with_schema_version(2).raw, keys)

    # Assert
    assert updated["future_field"] == {"added_by": "a newer app"}
    assert updated["schema_version"] == 2
    manifest.verify(updated, keys)


def test_tampering_breaks_the_signature(keys: VaultKeys) -> None:
    # Arrange
    signed = manifest.sign(_document(keys), keys)
    signed["display_name"] = "Someone else's vault"

    # Act / Assert
    with pytest.raises(DocVaultError) as caught:
        manifest.verify(signed, keys)
    assert caught.value.code == "VAULT_MANIFEST_TAMPERED"


def test_missing_integrity_is_rejected(keys: VaultKeys) -> None:
    document = _document(keys)
    with pytest.raises(DocVaultError):
        manifest.verify(document, keys)


def test_structure_rejects_a_third_fanout_level(keys: VaultKeys) -> None:
    # Arrange
    signed = manifest.sign(_document(keys), keys)
    signed["blob"]["fanout"] = [2, 2, 2]

    # Act / Assert
    with pytest.raises(DocVaultError) as caught:
        manifest.validate_structure(signed)
    assert caught.value.code == "VAULT_MANIFEST_INVALID"


def test_wrong_key_fingerprint_is_refused(keys: VaultKeys, tmp_path: Path) -> None:
    # Arrange
    other = derive_keys(bytes([3]) * 32)
    document = _document(other)
    signed = manifest.sign(document, other)
    path = tmp_path / "manifest.json"
    path.write_text(manifest.Manifest(signed).to_bytes().decode(), encoding="utf-8")

    # Act / Assert
    with pytest.raises(DocVaultError) as caught:
        manifest.load_and_verify(path, keys)
    assert caught.value.code == "VAULT_KEY_MISMATCH"


def test_manifest_bytes_are_readable_and_round_trip(keys: VaultKeys, tmp_path: Path) -> None:
    # Arrange
    signed = manifest.sign(_document(keys), keys)
    parsed = manifest.validate_structure(signed)
    path = tmp_path / "manifest.json"
    path.write_bytes(parsed.to_bytes())

    # Act
    loaded = manifest.load_and_verify(path, keys)

    # Assert
    assert loaded.raw == signed
