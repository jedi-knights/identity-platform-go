-- ADR-0009: ClientType (public / confidential) distinguishes OAuth clients
-- that can safely hold a secret from those that cannot. Public clients (SPAs,
-- native apps, MCP connectors in a browser tab) authenticate at the token
-- endpoint with PKCE proof of possession only; confidential clients
-- additionally present their secret.
--
-- Backwards compatibility: existing rows default to 'confidential', matching
-- the pre-ADR semantics where every client had a secret. The application
-- layer treats any value other than 'public' as confidential (fail closed),
-- so the column constraint is documentation rather than enforcement.

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS client_type TEXT NOT NULL DEFAULT 'confidential';
