-- Reverses the ADR-0023 jwks_uri column.
--
-- Down migrations are intentionally destructive — any per-row jwks_uri
-- information is lost. Production rollbacks should snapshot the column
-- before applying this if the data needs to be preserved.

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS jwks_uri;
