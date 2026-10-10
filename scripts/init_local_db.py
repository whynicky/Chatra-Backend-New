#!/usr/bin/env python3
"""Create missing ORM tables for a fresh local development/test database.

This is intentionally explicit and refuses production. Existing production
schemas must use reviewed migrations; this command performs no ALTER or DROP.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from urllib.parse import urlparse

BACKEND = Path(__file__).resolve().parents[1]
os.chdir(BACKEND)
sys.path.insert(0, str(BACKEND))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(BACKEND / ".env")

from db import DATABASE_URL, engine  # noqa: E402
from models import Base  # noqa: E402


def _is_local_database(url: str) -> bool:
    if url.startswith("sqlite:"):
        return True
    host = (urlparse(url).hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1", "db"}


if os.getenv("APP_ENV", "development").lower() == "production" or not _is_local_database(DATABASE_URL):
    raise SystemExit(
        "Refusing to initialize a non-local/production database. Use reviewed migrations instead."
    )

Base.metadata.create_all(bind=engine)
print("Local database initialized: missing tables created (no ALTER/DROP performed).")
