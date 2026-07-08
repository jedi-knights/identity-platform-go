-- ADR-0026: RFC 7522 SAML 2.0 Bearer Assertion Grant. trusted_issuer_cert
-- is the PEM-encoded X.509 certificate of the SAML IdP a client trusts
-- assertions from. Empty for clients that don't use the saml2-bearer
-- grant — defaults to '' to preserve pre-ADR-0026 behaviour for every
-- existing client.

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS trusted_issuer_cert TEXT NOT NULL DEFAULT '';
