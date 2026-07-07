-- SQLite equivalent of the postgres adapter's final schema shape (after its
-- 000001-000002 migrations). Written as one consolidated migration rather
-- than replaying each postgres migration step, since this is a new adapter
-- with no existing rows to carry forward. Dialect differences from postgres:
--   - No TIMESTAMPTZ — created_at/updated_at/email_verified_at/expires_at/
--     used_at are TEXT storing RFC3339 (UTC), written by the application
--     rather than relying on a dialect-specific now().
--   - active uses BOOLEAN (NUMERIC affinity; SQLite stores 0/1).

CREATE TABLE IF NOT EXISTS users (
    id                TEXT    PRIMARY KEY,
    email             TEXT    NOT NULL UNIQUE,
    name              TEXT    NOT NULL,
    password_hash     TEXT    NOT NULL,
    active            BOOLEAN NOT NULL DEFAULT 1,
    created_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL,
    email_verified_at TEXT
);

CREATE INDEX IF NOT EXISTS users_email_idx ON users (email);

CREATE TABLE IF NOT EXISTS verification_tokens (
    -- token_hash is the SHA-256 hex digest of the plaintext token. The
    -- plaintext is never stored.
    token_hash TEXT NOT NULL PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS verification_tokens_user_id_idx
    ON verification_tokens (user_id);

CREATE INDEX IF NOT EXISTS verification_tokens_expires_at_idx
    ON verification_tokens (expires_at);
