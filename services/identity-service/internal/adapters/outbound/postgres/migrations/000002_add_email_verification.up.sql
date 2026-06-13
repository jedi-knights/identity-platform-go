-- Email verification: track when a user proves they control the address on
-- file, and store the one-time tokens that drive the flow.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS verification_tokens (
    -- token_hash is the SHA-256 hex digest of the plaintext token. The
    -- plaintext is never stored.
    token_hash  TEXT        PRIMARY KEY,
    user_id     TEXT        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS verification_tokens_user_id_idx
    ON verification_tokens (user_id);

CREATE INDEX IF NOT EXISTS verification_tokens_expires_at_idx
    ON verification_tokens (expires_at);
