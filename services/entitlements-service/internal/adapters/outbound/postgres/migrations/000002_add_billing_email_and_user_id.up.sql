-- Add billing_email + user_id to accounts (E7-S1a / #209).
--
-- Rationale (derived from Epic 7 / ADR-0028):
--   billing_email  — the email the account is billed under; matches the
--                    seat owner's user record at creation, may drift later
--                    if the account is transferred.
--   user_id        — natural key for a personal account (1:1 with a user).
--                    NULL for accounts created via invite/admin that have
--                    no single "personal" owner.
--
-- No existing data → NOT NULL on billing_email is safe. user_id has a
-- partial-unique constraint so multiple non-personal accounts (user_id
-- NULL) can coexist without collision on the UNIQUE index.

ALTER TABLE accounts
  ADD COLUMN IF NOT EXISTS billing_email TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS user_id TEXT;

-- Drop the default now that the column exists; new rows must supply a
-- real email. (Retaining a permanent default would let a caller silently
-- create rows with empty billing_email.)
ALTER TABLE accounts
  ALTER COLUMN billing_email DROP DEFAULT;

-- Partial-unique index: uniqueness on user_id only among personal
-- accounts (WHERE user_id IS NOT NULL). Full-column UNIQUE would reject
-- multiple NULLs on some Postgres versions and would incorrectly treat
-- non-personal accounts as conflicting.
CREATE UNIQUE INDEX IF NOT EXISTS accounts_user_id_unique_idx
  ON accounts (user_id)
  WHERE user_id IS NOT NULL;
