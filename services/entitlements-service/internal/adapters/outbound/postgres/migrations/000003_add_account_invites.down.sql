-- Reverse of 000003_add_account_invites.up.sql.

DROP INDEX IF EXISTS account_invites_no_dup_open_idx;
DROP INDEX IF EXISTS account_invites_pending_by_token_idx;
DROP INDEX IF EXISTS account_invites_pending_by_account_idx;
DROP TABLE IF EXISTS account_invites;
