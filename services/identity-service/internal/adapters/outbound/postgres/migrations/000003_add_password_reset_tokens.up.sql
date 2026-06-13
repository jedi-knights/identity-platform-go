-- Password reset: one-time tokens for proving control of an email when the
-- user wants to set a new password.
--
-- A separate table from verification_tokens. The two flows can have
-- independent TTLs, rate limits, and revocation policies; conflating them
-- would force callers to special-case the consumer column.

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash  TEXT        PRIMARY KEY,
    user_id     TEXT        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS password_reset_tokens_user_id_idx
    ON password_reset_tokens (user_id);

CREATE INDEX IF NOT EXISTS password_reset_tokens_expires_at_idx
    ON password_reset_tokens (expires_at);
