from __future__ import annotations

import pytest
from sqlalchemy import create_engine, insert, select
from sqlalchemy.orm import Session

from app.core.errors import DocVaultError
from app.db.enums import EntityType, PersonRole, RoleName
from app.db.models.entities import EntityPerson
from app.db.models.identity import UserRole
from app.services import entities

from .factories import make_user


def test_entity_creation_encrypts_fields_and_creates_identifier(database_url: str, keys) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        actor_id = make_user(connection)
        connection.execute(insert(UserRole).values(user_id=actor_id, role=RoleName.EDITOR))

    try:
        with Session(engine) as session, session.begin():
            record = entities.create_entity(
                session,
                keys,
                actor_id=actor_id,
                entity_type=EntityType.COMPANY,
                legal_name="Example Holdings",
                display_name="Example",
                identifiers=({"id_type": "pan", "value": "AABCA1234B"},),
            )
            result = entities.entity_data(record, keys)
            identifier = entities.list_identifiers(session, record.id)[0]
            identifier_result = entities.identifier_data(identifier, keys)

            assert record.legal_name_enc != b"Example Holdings"
            assert result["legal_name"] == "Example Holdings"
            assert identifier.value_enc != b"AABCA1234B"
            assert identifier_result["value"] is None
            assert identifier_result["value_masked"] == "AA******4B"
    finally:
        engine.dispose()


def test_duplicate_identifier_is_rejected(database_url: str, keys) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        actor_id = make_user(connection)

    try:
        with Session(engine) as session, session.begin():
            first = entities.create_entity(
                session,
                keys,
                actor_id=actor_id,
                entity_type=EntityType.COMPANY,
                legal_name="First Entity",
                identifiers=({"id_type": "pan", "value": "AABCA1234B"},),
            )
            assert first.id is not None

        def duplicate_attempt() -> None:
            with Session(engine) as session, session.begin():
                entities.create_entity(
                    session,
                    keys,
                    actor_id=actor_id,
                    entity_type=EntityType.COMPANY,
                    legal_name="Second Entity",
                    identifiers=({"id_type": "pan", "value": "AABCA1234B"},),
                )

        with pytest.raises(DocVaultError) as caught:
            duplicate_attempt()
        assert caught.value.code == "CONFLICT"
    finally:
        engine.dispose()


def test_individual_creation_has_mandatory_self_link(database_url: str, keys) -> None:
    engine = create_engine(database_url)
    with engine.begin() as connection:
        actor_id = make_user(connection)

    try:
        with Session(engine) as session, session.begin():
            record = entities.create_entity(
                session,
                keys,
                actor_id=actor_id,
                entity_type=EntityType.INDIVIDUAL,
                legal_name="Example Person",
            )
            links = session.execute(
                select(EntityPerson).where(
                    EntityPerson.entity_id == record.id,
                    EntityPerson.role == PersonRole.SELF,
                )
            ).scalars()
            assert len(tuple(links)) == 1
    finally:
        engine.dispose()
