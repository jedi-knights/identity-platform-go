-- ADR-0023: jwks_uri (RFC 7591 §2 registration metadata) advertises where a
-- client publishes its public signing key(s), for RFC 7523 JWT-bearer
-- client authentication. Empty string means the client has not opted in —
-- client_secret remains its only credential, matching every existing row.

ALTER TABLE oauth_clients
    ADD COLUMN jwks_uri TEXT NOT NULL DEFAULT '';
