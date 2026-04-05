-- Normalize: replace TEXT[] columns on oauth_clients with proper join tables.
-- This satisfies 1NF by removing repeating groups and enables efficient
-- "which clients have scope X?" queries via indexed FK lookups.

ALTER TABLE oauth_clients DROP COLUMN IF EXISTS scopes;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS grant_types;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS redirect_uris;

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
