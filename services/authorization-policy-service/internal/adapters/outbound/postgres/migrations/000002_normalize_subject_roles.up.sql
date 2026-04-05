-- Normalize: replace the policies table (subject_id → TEXT[] roles) with a
-- subject_roles join table so each (subject, role) pair is a single atomic row.
-- This satisfies 1NF and removes the repeating-group violation.

DROP TABLE IF EXISTS policies;

CREATE TABLE IF NOT EXISTS subject_roles (
    subject_id TEXT NOT NULL,
    role_name  TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    PRIMARY KEY (subject_id, role_name)
);

-- Allows efficient "who has role X?" queries without a full table scan.
CREATE INDEX IF NOT EXISTS subject_roles_role_name_idx ON subject_roles(role_name);
