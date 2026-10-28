"""Declarative base and small helpers shared by every model."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from sqlalchemy import Enum, MetaData
from sqlalchemy.orm import DeclarativeBase

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """One metadata object so Alembic sees the whole schema."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def pg_enum(enum_cls: type[StrEnum], name: str) -> Enum:
    """A PostgreSQL enum that stores the lowercase member value."""
    return Enum(
        enum_cls,
        name=name,
        values_callable=lambda members: [member.value for member in members],
        validate_strings=True,
    )


HEX64 = r"^[0-9a-f]{64}$"
MONTH = r"^[0-9]{4}-(0[1-9]|1[0-2])$"


def json_default() -> dict[str, Any]:
    return {}


def empty_json_sql() -> str:
    return "'{}'::jsonb"
