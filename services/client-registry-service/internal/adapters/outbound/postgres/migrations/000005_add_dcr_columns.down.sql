ALTER TABLE oauth_clients DROP COLUMN IF EXISTS registration_access_token_hash;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS token_endpoint_auth_method;
