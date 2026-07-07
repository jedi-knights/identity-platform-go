-- SQLite equivalent of the postgres adapter's final schema shape (after its
-- 000001-000002 migrations, which normalized the original policies(subject_id,
-- roles TEXT[]) table into subject_roles). Written as one consolidated
-- migration rather than replaying each postgres migration step, since this
-- is a new adapter with no existing rows to carry forward — the policies
-- table never exists here.

CREATE TABLE IF NOT EXISTS roles (
    name TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_name TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    resource  TEXT NOT NULL,
    action    TEXT NOT NULL,
    PRIMARY KEY (role_name, resource, action)
);

CREATE TABLE IF NOT EXISTS subject_roles (
    subject_id TEXT NOT NULL,
    role_name  TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    PRIMARY KEY (subject_id, role_name)
);

CREATE INDEX IF NOT EXISTS subject_roles_role_name_idx ON subject_roles(role_name);
