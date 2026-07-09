# RFC 7522 — SAML 2.0 Bearer Assertion Profile for OAuth 2.0
# https://datatracker.ietf.org/doc/html/rfc7522
# Lets a client exchange a SAML 2.0 assertion identifying the resource
# owner for an OAuth access token — a federation bridge for organizations
# whose identity provider speaks SAML rather than OIDC.
#
# ADR-0026 — SAML 2.0 Bearer Assertion Grant (RFC 7522)
# docs/adr/0026-saml2-bearer-assertion-grant.md
# Scoped to RFC 7522 §2.1 (assertion as authorization grant) only — §2.2
# (SAML for client authentication) is not implemented, mirroring how this
# platform's RFC 7521/7523 work covers the JWT analogue of client
# authentication separately. The client authenticates itself exactly like
# every other grant (client_id/client_secret); the assertion is a separate
# artifact identifying the resource owner, not a client-authentication
# mechanism. Trust is established via an optional trusted_issuer_cert
# field on the registered OAuth client (mirrors RFC 7521/7523's jwks_uri
# field precedent) — these scenarios generate their own self-signed test
# certificate and signed assertion in-process, mirroring how PKCE
# scenarios generate their own code_verifier rather than depending on a
# fixture or a real external IdP. No refresh token is issued for this
# grant — an assertion grant's natural re-authorization mechanism is
# presenting a fresh, short-lived assertion from the IdP.
Feature: SAML 2.0 Bearer Assertion Grant

  @topology:auth-client-registry-saml-bearer
  Scenario: A valid signed SAML assertion is exchanged for an access token with no refresh token
    Given a registered confidential OAuth client with scopes "read" and grant type "urn:ietf:params:oauth:grant-type:saml2-bearer" trusting a generated SAML issuer
    When the client requests a token using the saml2-bearer grant with subject "saml-user-1"
    Then the response status is 200
    And the response has a non-empty "access_token"
    And the response does not have a "refresh_token" field

  @topology:auth-client-registry-saml-bearer
  Scenario: The issued token's introspection reflects the assertion's subject
    Given a registered confidential OAuth client with scopes "read" and grant type "urn:ietf:params:oauth:grant-type:saml2-bearer" trusting a generated SAML issuer
    When the client requests a token using the saml2-bearer grant with subject "saml-user-42"
    Then the response status is 200
    And the "access_token" from the last response is captured as "access_token"
    And the client introspects the access_token
    Then the response status is 200
    And the response "sub" is "saml-user-42"

  @topology:auth-client-registry-saml-bearer
  Scenario: An assertion targeting the wrong audience is rejected
    Given a registered confidential OAuth client with scopes "read" and grant type "urn:ietf:params:oauth:grant-type:saml2-bearer" trusting a generated SAML issuer
    When the client requests a token using the saml2-bearer grant with subject "saml-user-1" and audience "https://someone-else.example.com/oauth/token"
    Then the response status is 400
    And the response "error" is "invalid_grant"

  @topology:auth-client-registry-saml-bearer
  Scenario: A client without a trusted issuer certificate is rejected
    Given a registered confidential OAuth client with scopes "read" and grant type "urn:ietf:params:oauth:grant-type:saml2-bearer" with no trusted SAML issuer
    When the client requests a token using the saml2-bearer grant with subject "saml-user-1"
    Then the response status is 400
    And the response "error" is "invalid_grant"

  @topology:auth-metadata
  Scenario: The metadata document advertises the saml2-bearer grant type
    When the client sends a GET request to "/.well-known/oauth-authorization-server"
    Then the response status is 200
    And the response "grant_types_supported" array contains "urn:ietf:params:oauth:grant-type:saml2-bearer"
