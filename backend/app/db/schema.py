"""The schema version this build understands.

Kept in one place so the manifest, the database identity row, and the Alembic
head cannot drift. The initial revision ``c02412ca4b8b`` is version 1.
"""

from __future__ import annotations

SCHEMA_VERSION = 1

# The Alembic revision that creates version 1. Later revisions update both.
INITIAL_REVISION = "c02412ca4b8b"
