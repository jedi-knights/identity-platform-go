DROP INDEX IF EXISTS verification_tokens_expires_at_idx;
DROP INDEX IF EXISTS verification_tokens_user_id_idx;
DROP TABLE IF EXISTS verification_tokens;
ALTER TABLE users DROP COLUMN IF EXISTS email_verified_at;
