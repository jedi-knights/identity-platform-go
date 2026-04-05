-- Drop in reverse dependency order so foreign-key constraints are satisfied.
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS policies;
