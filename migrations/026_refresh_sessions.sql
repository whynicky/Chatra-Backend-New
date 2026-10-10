-- Additive refresh-token rotation/replay protection for AUD-005.
-- Apply through the reviewed production migration process before deploying the
-- cookie-session backend. No existing rows or token_version values are changed.

CREATE TABLE IF NOT EXISTS refresh_sessions (
    jti VARCHAR(80) PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_version INTEGER NOT NULL,
    client_type VARCHAR(16) NOT NULL DEFAULT 'native',
    expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITHOUT TIME ZONE NULL,
    replaced_by_jti VARCHAR(80) NULL
);

CREATE INDEX IF NOT EXISTS ix_refresh_sessions_user_id
    ON refresh_sessions(user_id);
CREATE INDEX IF NOT EXISTS ix_refresh_sessions_expires_at
    ON refresh_sessions(expires_at);
