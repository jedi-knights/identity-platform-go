-- SQLite equivalent of the postgres adapter's schema. Dialect differences:
--   - No TIMESTAMPTZ — created_at is TEXT storing RFC3339 (UTC), written by
--     the application rather than relying on a dialect-specific now().

CREATE TABLE IF NOT EXISTS resources (
    id          TEXT NOT NULL PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    owner_id    TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
