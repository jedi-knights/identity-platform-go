CREATE TABLE IF NOT EXISTS oauth_clients (
    id            TEXT        PRIMARY KEY,
    secret        TEXT        NOT NULL,
    name          TEXT        NOT NULL,
    scopes        TEXT[]      NOT NULL DEFAULT '{}',
    grant_types   TEXT[]      NOT NULL DEFAULT '{}',
    redirect_uris TEXT[]      NOT NULL DEFAULT '{}',
    active        BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
