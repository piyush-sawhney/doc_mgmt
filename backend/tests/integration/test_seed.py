"""The seeded catalogue from docs/13 §4.

Seed names are encrypted, so these tests need a vault key. They also prove the
idempotence rule: a second run changes nothing, and a renamed type survives.
"""

from __future__ import annotations

import pytest
from sqlalchemy import Connection, func, select, text, update

from app.core.errors import DocVaultError
from app.crypto.keys import decrypt_column, encrypt_column
from app.db.enums import ConfLevel, SideKind
from app.db.models import DocType
from app.db.seed import CATALOGUE, catalogue_size, seed_catalogue


def test_seed_inserts_eight_categories_and_every_documented_type(
    seeded, connection: Connection
) -> None:
    expected_categories, expected_types = catalogue_size()
    assert expected_categories == 8
    assert expected_types == 73
    assert seeded.categories_inserted == 8
    assert seeded.types_inserted == 73
    assert seeded.categories_total == 8
    assert seeded.types_total == 73

    categories = connection.execute(
        select(func.count()).select_from(DocType).where(DocType.parent_id.is_(None))
    ).scalar_one()
    types = connection.execute(
        select(func.count()).select_from(DocType).where(DocType.parent_id.is_not(None))
    ).scalar_one()
    assert (categories, types) == (8, 73)

    non_system = connection.execute(
        select(func.count()).select_from(DocType).where(DocType.is_system.is_(False))
    ).scalar_one()
    assert non_system == 0

    codes = set(connection.execute(select(DocType.code)).scalars())
    expected_codes = {category.code for category in CATALOGUE}
    expected_codes.update(spec.code for category in CATALOGUE for spec in category.types)
    assert codes == expected_codes


def test_seed_is_idempotent(seeded, connection: Connection, keys) -> None:
    before = connection.execute(select(func.count()).select_from(DocType)).scalar_one()

    again = seed_catalogue(connection, meta_key=keys.meta_key)
    connection.commit()

    after = connection.execute(select(func.count()).select_from(DocType)).scalar_one()
    assert again.inserted == 0
    assert again.categories_total == 8
    assert again.types_total == 73
    assert after == before


def test_seed_does_not_overwrite_a_renamed_type(seeded, connection: Connection, keys) -> None:
    custom = encrypt_column(keys.meta_key, "doc_types", "name", "Custom PAN")
    assert custom is not None
    connection.execute(update(DocType).where(DocType.code == "pan_card").values(name_enc=custom))
    connection.commit()

    seed_catalogue(connection, meta_key=keys.meta_key)
    connection.commit()

    stored = connection.execute(
        select(DocType.name_enc).where(DocType.code == "pan_card")
    ).scalar_one()
    assert decrypt_column(keys.meta_key, "doc_types", "name", stored) == "Custom PAN"


def test_seed_refuses_to_reparent_a_seeded_code(seeded, connection: Connection, keys) -> None:
    """A code that moved elsewhere is a conflict, not something to overwrite."""
    property_category = connection.execute(
        select(DocType.id).where(DocType.code == "property")
    ).scalar_one()
    connection.execute(
        update(DocType).where(DocType.code == "pan_card").values(parent_id=property_category)
    )
    connection.commit()

    with pytest.raises(DocVaultError) as excinfo:
        seed_catalogue(connection, meta_key=keys.meta_key)
    assert excinfo.value.code == "SEED_CONFLICT"
    connection.rollback()


def test_seed_names_are_encrypted(seeded, connection: Connection, keys) -> None:
    stored = connection.execute(
        select(DocType.name_enc).where(DocType.code == "pan_card")
    ).scalar_one()

    assert b"PAN card" not in stored
    assert decrypt_column(keys.meta_key, "doc_types", "name", stored) == "PAN card"


def test_front_and_back_types_carry_a_side_hint(seeded, connection: Connection) -> None:
    sides = dict(
        connection.execute(
            select(DocType.code, DocType.side).where(
                DocType.code.in_(
                    ["pan_card_front", "pan_card_back", "aadhaar_front", "aadhaar_back"]
                )
            )
        ).all()
    )
    assert sides == {
        "pan_card_front": SideKind.FRONT,
        "pan_card_back": SideKind.BACK,
        "aadhaar_front": SideKind.FRONT,
        "aadhaar_back": SideKind.BACK,
    }


def test_seed_defaults_match_the_classification_document(seeded, connection: Connection) -> None:
    rows = connection.execute(
        select(
            DocType.code,
            DocType.default_confidentiality,
            DocType.requires_expiry,
            DocType.parent_id,
        )
    ).all()
    by_code = {row.code: row for row in rows}

    assert by_code["pan_card"].default_confidentiality == ConfLevel.SENSITIVE
    assert by_code["pan_card"].requires_expiry is False
    assert by_code["passport"].requires_expiry is True
    assert by_code["sale_deed"].default_confidentiality == ConfLevel.RESTRICTED
    assert by_code["annual_return"].default_confidentiality == ConfLevel.NORMAL
    assert by_code["annual_return"].requires_expiry is True


def test_every_type_has_a_category(seeded, connection: Connection) -> None:
    orphaned = connection.execute(
        text(
            "SELECT count(*) FROM doc_types child "
            "LEFT JOIN doc_types parent ON parent.id = child.parent_id "
            "WHERE child.parent_id IS NOT NULL AND parent.parent_id IS NOT NULL"
        )
    ).scalar_one()
    assert orphaned == 0


def test_seed_requires_a_key_that_can_encrypt(connection: Connection) -> None:
    with pytest.raises(TypeError):
        seed_catalogue(connection)  # type: ignore[call-arg]
