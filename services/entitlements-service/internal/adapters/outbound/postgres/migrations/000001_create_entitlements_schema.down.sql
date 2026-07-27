-- Reverse of 000001_create_entitlements_schema.up.sql.
-- Drop order respects foreign-key dependencies (children first).

DROP TABLE IF EXISTS account_plans;
DROP TABLE IF EXISTS account_seats;
DROP TABLE IF EXISTS accounts;

DROP TABLE IF EXISTS plan_bundles;
DROP TABLE IF EXISTS plans;

DROP TABLE IF EXISTS bundle_resources;
DROP TABLE IF EXISTS bundles;
DROP TABLE IF EXISTS resources;

-- pgcrypto is left installed — other services in this cluster may depend on it.
