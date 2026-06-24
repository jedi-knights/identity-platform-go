-- Reverses the ADR-0009 ClientType column.
--
-- Down migrations are intentionally destructive — any per-row client_type
-- information is lost. Production rollbacks should snapshot the column
-- before applying this if the data needs to be preserved.

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS client_type;
