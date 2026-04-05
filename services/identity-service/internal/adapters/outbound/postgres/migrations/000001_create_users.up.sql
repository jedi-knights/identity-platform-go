CREATE TABLE IF NOT EXISTS users (
    id            TEXT        PRIMARY KEY,
    email         TEXT        NOT NULL UNIQUE,
    name          TEXT        NOT NULL,
    password_hash TEXT        NOT NULL,
    active        BOOLEAN     NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS users_email_idx ON users (email);
