-- ADR-0026: RFC 7522 SAML 2.0 Bearer Assertion Grant. Mirrors the postgres
-- adapter's 000007 migration.

ALTER TABLE oauth_clients ADD COLUMN trusted_issuer_cert TEXT NOT NULL DEFAULT '';
