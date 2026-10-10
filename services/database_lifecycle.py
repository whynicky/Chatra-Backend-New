"""Explicit database readiness checks used by application and job lifecycles."""

from __future__ import annotations

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.sql.schema import MetaData


class DatabaseReadinessError(RuntimeError):
    """The configured database is unavailable or has not been migrated."""


def check_database_ready(engine: Engine, metadata: MetaData) -> None:
    """Verify connectivity and the required schema without mutating anything."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        present = set(inspect(engine).get_table_names())
    except Exception as exc:  # keep credentials/DSNs out of the message
        raise DatabaseReadinessError(
            "Database is unavailable. Check connectivity and DATABASE_URL."
        ) from exc

    missing = sorted(set(metadata.tables) - present)
    if missing:
        preview = ", ".join(missing[:8])
        suffix = " …" if len(missing) > 8 else ""
        raise DatabaseReadinessError(
            f"Database schema is not ready; missing tables: {preview}{suffix}. "
            "Run the reviewed migration or the explicit local init command."
        )
