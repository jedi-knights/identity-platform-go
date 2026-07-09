-- Reverses the ADR-0023 jwks_uri column. Not executed by this adapter's
-- RunMigrations (which only applies *.up.sql, forward-only) — kept for
-- documentation symmetry with the postgres adapter's migration set.

ALTER TABLE oauth_clients
    DROP COLUMN jwks_uri;
