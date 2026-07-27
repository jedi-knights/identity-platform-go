-- Reverse of 000002_add_billing_email_and_user_id.up.sql.

DROP INDEX IF EXISTS accounts_user_id_unique_idx;

ALTER TABLE accounts
  DROP COLUMN IF EXISTS user_id,
  DROP COLUMN IF EXISTS billing_email;
