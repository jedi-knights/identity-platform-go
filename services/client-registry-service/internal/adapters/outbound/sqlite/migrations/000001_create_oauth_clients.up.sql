-- SQLite equivalent of the postgres adapter's final schema shape (after its
-- 000001-000005 migrations). Written as one consolidated migration rather
-- than replaying each postgres migration step, since this is a new adapter
-- with no existing rows to carry forward. Dialect differences from postgres:
--   - No TEXT[] array columns (never existed here) — scopes/grant_types/
--     redirect_uris go straight into join tables, satisfying 1NF from the start.
--   - No TIMESTAMPTZ — created_at/updated_at are TEXT storing RFC3339 (UTC),
--     written by the application rather than relying on a dialect-specific now().
--   - active uses BOOLEAN (NUMERIC affinity; SQLite stores 0/1).

CREATE TABLE IF NOT EXISTS oauth_clients (
    id                             TEXT    PRIMARY KEY,
    secret                         TEXT    NOT NULL,
    name                           TEXT    NOT NULL,
    client_type                    TEXT    NOT NULL DEFAULT 'confidential',
    actor_type                     TEXT    NOT NULL DEFAULT 'service',
    token_endpoint_auth_method     TEXT    NOT NULL DEFAULT 'client_secret_basic',
    registration_access_token_hash TEXT    NOT NULL DEFAULT '',
    active                         BOOLEAN NOT NULL DEFAULT 1,
    created_at                     TEXT    NOT NULL,
    updated_at                     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS client_scopes (
    client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scope     TEXT NOT NULL,
    PRIMARY KEY (client_id, scope)
);

CREATE TABLE IF NOT EXISTS client_grant_types (
    client_id  TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    grant_type TEXT NOT NULL,
    PRIMARY KEY (client_id, grant_type)
);

CREATE TABLE IF NOT EXISTS client_redirect_uris (
    client_id    TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    PRIMARY KEY (client_id, redirect_uri)
);
