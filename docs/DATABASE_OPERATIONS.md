# Database startup and scheduled-job operations

Application imports are read-only. API startup checks connectivity and verifies that every ORM table exists; it never creates or alters schemas. A missing dependency fails startup with a redacted, actionable error.

## Fresh local development

Set a local SQLite/localhost/container `DATABASE_URL`, keep `APP_ENV=development`, and run:

```sh
venv/bin/python scripts/init_local_db.py
```

The command creates missing tables only and refuses non-local or production targets. Tests create their temporary schema explicitly in their fixture.

## Existing and production databases

Use the reviewed, backed-up migration procedure. For the current release, `migrations/026_refresh_sessions.sql` must be applied before the cookie-session backend starts. The API readiness check will fail rather than silently mutate an older schema. Do not use the local initialization command against production.

## Multiple workers and scheduled jobs

API workers default to `BACKGROUND_JOBS_ENABLED=0`. Run exactly one supervised process per environment with:

```sh
venv/bin/python scripts/run_background_jobs.py
```

For local single-process compatibility only, `BACKGROUND_JOBS_ENABLED=1` starts the loops inside that API process. Never enable it on more than one web worker. Shutdown cancels and awaits all locally started tasks.
