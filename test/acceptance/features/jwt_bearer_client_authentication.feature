# RFC 7521 — Assertion Framework for OAuth 2.0 Client Authentication
# RFC 7523 — JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication
# docs/adr/0023-jwt-bearer-client-authentication.md
# A client that has registered a jwks_uri (RFC 7591 §2) can authenticate
# at the token endpoint by presenting a JWT it signs with its own private
# key — client_assertion + client_assertion_type=...jwt-bearer — instead
# of a client_secret. auth-server verifies the signature against the
# client's registered JWKS, then RFC 7523 §3's claim set: iss and sub
# must both equal the supplied client_id, aud must name this server's
# issuer, exp must be present and unexpired, and jti must be present and
# not already used (replay protection). Scoped to client_credentials,
# refresh_token, and authorization_code per ADR-0023 — this feature
# exercises client_credentials, the primary service-to-service case.
Feature: JWT-Bearer Client Authentication

  @topology:auth-client-registry
  Scenario: A client authenticates with a JWT-bearer assertion instead of a client_secret
    Given a registered confidential OAuth client with scopes "read", grant type "client_credentials", and a JWT-bearer signing key
    When the client requests a token using the client_credentials grant with a JWT-bearer assertion
    Then the response status is 200
    And the response has a non-empty "access_token"

  @topology:auth-client-registry
  Scenario: A JWT-bearer assertion signed by the wrong key is rejected
    Given a registered confidential OAuth client with scopes "read", grant type "client_credentials", and a JWT-bearer signing key
    When the client requests a token using the client_credentials grant with a JWT-bearer assertion signed by a different key
    Then the response status is 401
    And the response "error" is "invalid_client"

  @topology:auth-client-registry
  Scenario: A JWT-bearer assertion cannot be replayed
    Given a registered confidential OAuth client with scopes "read", grant type "client_credentials", and a JWT-bearer signing key
    And the client requests a token using the client_credentials grant with a JWT-bearer assertion
    When the client requests a token using the client_credentials grant with the same JWT-bearer assertion again
    Then the response status is 401
    And the response "error" is "invalid_client"

  @topology:auth-client-registry
  Scenario: A client without a registered jwks_uri cannot authenticate via JWT-bearer assertion
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    When the client requests a token using the client_credentials grant with a JWT-bearer assertion signed by a different key
    Then the response status is 401
    And the response "error" is "invalid_client"
