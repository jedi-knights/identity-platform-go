# RFC 7009 — OAuth 2.0 Token Revocation
# https://datatracker.ietf.org/doc/html/rfc7009
# Lets a client notify the authorization server that a previously
# obtained token is no longer needed, so it can be invalidated. Revoking
# an already-invalid or unknown token is not an error (§2.2) — the
# endpoint's job is to guarantee the token is unusable afterward, not to
# report on the token's prior state.
@topology:auth-client-registry
Feature: Token Revocation

  Scenario: A valid access token is revoked and becomes inactive
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "access_token"
    When the client revokes the access_token
    Then the response status is 200
    And the response header "Cache-Control" is "no-store"

  Scenario: The revoked token is inactive on introspection
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "access_token"
    And the client revokes the access_token
    When the client introspects the access_token
    Then the response status is 200
    And the response "active" is false

  Scenario: Revoking an already-revoked token is idempotent
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "access_token"
    And the client revokes the access_token
    When the client revokes the access_token
    Then the response status is 200

  Scenario: An unsupported token_type_hint is rejected
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "access_token"
    When the client revokes the access_token with token_type_hint "id_token"
    Then the response status is 400
    And the response "error" is "unsupported_token_type"

  Scenario: Revocation without client authentication is rejected
    When the client attempts to revoke a token without authenticating
    Then the response status is 401
    And the response "error" is "invalid_client"
