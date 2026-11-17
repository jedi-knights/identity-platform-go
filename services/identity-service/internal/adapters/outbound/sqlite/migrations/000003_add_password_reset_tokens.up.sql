-- Password reset: one-time tokens for proving control of an email when the
-- user wants to set a new password. SQLite-dialect twin of postgres
-- migration 000004 (sqlite is one number behind: its 000001 already
-- bundled users + verification_tokens, see 000002_add_user_preferences).
--
-- A separate table from verification_tokens so the two flows can have
-- independent TTLs, rate limits, and revocation policies.
-- TIMESTAMPTZ does not exist in SQLite: TEXT + application-side
-- sqliteTimeLayout (see db.go) preserves chronological ordering.

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash TEXT NOT NULL PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS password_reset_tokens_user_id_idx
    ON password_reset_tokens (user_id);

CREATE INDEX IF NOT EXISTS password_reset_tokens_expires_at_idx
    ON password_reset_tokens (expires_at);
