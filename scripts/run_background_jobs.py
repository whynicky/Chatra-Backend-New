#!/usr/bin/env python3
"""Run Chatra scheduled jobs in one dedicated process.

API workers keep BACKGROUND_JOBS_ENABLED=0. Start exactly one instance of this
process per environment; database-level dedup remains a second line of defense.
"""

from __future__ import annotations

import asyncio

from db import engine
from models import Base
from services.database_lifecycle import check_database_ready
from services.deadline_checker import deadline_checker_loop
from services.deadline_reminder import deadline_reminder_loop


async def main() -> None:
    check_database_ready(engine, Base.metadata)
    await asyncio.gather(deadline_checker_loop(), deadline_reminder_loop())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
