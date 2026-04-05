DROP TABLE IF EXISTS client_redirect_uris;
DROP TABLE IF EXISTS client_grant_types;
DROP TABLE IF EXISTS client_scopes;

ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS scopes        TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS grant_types   TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS redirect_uris TEXT[] NOT NULL DEFAULT '{}';
