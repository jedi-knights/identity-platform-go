-- policies maps each subject (user/client) to a set of role names.
-- The subject_id is stable across the lifetime of the subject; roles is kept
-- as a text array so the full policy can be read and written in a single row.
CREATE TABLE IF NOT EXISTS policies (
    subject_id TEXT PRIMARY KEY,
    roles      TEXT[] NOT NULL DEFAULT '{}'
);

-- roles stores the canonical definition of a role by name.
CREATE TABLE IF NOT EXISTS roles (
    name TEXT PRIMARY KEY
);

-- role_permissions stores the (resource, action) pairs that belong to a role.
-- The composite primary key prevents duplicate permission entries.
-- ON DELETE CASCADE removes permissions automatically when the parent role is deleted.
CREATE TABLE IF NOT EXISTS role_permissions (
    role_name TEXT    NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    resource  TEXT    NOT NULL,
    action    TEXT    NOT NULL,
    PRIMARY KEY (role_name, resource, action)
);
