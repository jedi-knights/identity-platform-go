-- ADR-0013: RFC 7591 Dynamic Client Registration. Two new columns
-- support the registration flow:
--
-- * token_endpoint_auth_method records which RFC 7591 auth method the
--   client uses at the token endpoint. Defaults to 'client_secret_basic'
--   to preserve pre-ADR-0013 behaviour (every existing client has a
--   secret and authenticates with Basic). New public clients registered
--   via POST /register set this to 'none'.
--
-- * registration_access_token_hash is the bcrypt hash of the RFC 7592
--   registration access token. It is empty for clients created via the
--   admin POST /clients route — those clients cannot be managed via the
--   RFC 7592 endpoints. Dynamically-registered clients always carry a
--   non-empty hash.

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic';

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS registration_access_token_hash TEXT NOT NULL DEFAULT '';
