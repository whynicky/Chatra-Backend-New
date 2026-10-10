import os
import subprocess
import sys

import pytest
from sqlalchemy import create_engine

from models import Base
from services.database_lifecycle import DatabaseReadinessError, check_database_ready


def test_fresh_database_requires_explicit_initialization(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    with pytest.raises(DatabaseReadinessError, match="missing tables"):
        check_database_ready(engine, Base.metadata)


def test_initialized_and_existing_database_are_ready(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'ready.db'}")
    Base.metadata.create_all(bind=engine)
    check_database_ready(engine, Base.metadata)
    # A second readiness check is read-only and remains compatible.
    check_database_ready(engine, Base.metadata)


def test_importing_main_does_not_create_or_connect_database(tmp_path):
    db_path = tmp_path / "import-must-not-create.db"
    env = os.environ.copy()
    env.update({
        "DATABASE_URL": f"sqlite:///{db_path}",
        "SECRET_KEY": "test-secret-key",
        "REFRESH_SECRET_KEY": "test-refresh-secret-key",
        "APP_ENV": "test",
    })
    result = subprocess.run(
        [sys.executable, "-c", "import main"],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not db_path.exists()
