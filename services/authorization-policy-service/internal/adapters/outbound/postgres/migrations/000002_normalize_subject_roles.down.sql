DROP TABLE IF EXISTS subject_roles;

CREATE TABLE IF NOT EXISTS policies (
    subject_id TEXT PRIMARY KEY,
    roles      TEXT[] NOT NULL DEFAULT '{}'
);
