# RFC 7591 — OAuth 2.0 Dynamic Client Registration Protocol
# https://datatracker.ietf.org/doc/html/rfc7591
# Lets a client register itself with the authorization server over HTTP
# (POST /register) instead of an out-of-band administrative process,
# receiving back a client_id (and, for confidential clients, a
# client_secret) plus the credentials needed to manage that registration
# later.
#
# RFC 7592 — OAuth 2.0 Dynamic Client Registration Management Protocol
# https://datatracker.ietf.org/doc/html/rfc7592
# Defines the companion GET/PUT/DELETE operations at the
# registration_client_uri RFC 7591 hands back, authenticated by the
# registration_access_token bearer credential from the same response —
# not the client_secret.
#
# ADR-0013 — Dynamic Client Registration
# docs/adr/0013-dynamic-client-registration.md
# Registration is open by default (no initial-access-token gate is
# implemented). A public client (token_endpoint_auth_method "none")
# never receives a client_secret. Presenting the wrong
# registration_access_token for a real client_id returns 404, not
# 401/403 — collapsing "wrong credential" and "doesn't exist" into one
# response so registration existence can't be probed.
@topology:client-registry-dcr
Feature: Dynamic Client Registration

  Scenario: Registering a public client issues no client_secret
    When the client submits a dynamic client registration request:
      | client_name                | acceptance-test-public-client |
      | redirect_uris               | https://example.com/callback  |
      | token_endpoint_auth_method   | none                           |
    Then the response status is 201
    And the response header "Cache-Control" is "no-store"
    And the response does not have a "client_secret" field
    And the response "token_endpoint_auth_method" is "none"
    And the response has a non-empty "registration_access_token"
    And the response has a non-empty "registration_client_uri"

  Scenario: Registering a confidential client issues a client_secret
    When the client submits a dynamic client registration request:
      | client_name                | acceptance-test-confidential-client |
      | redirect_uris               | https://example.com/callback         |
      | token_endpoint_auth_method   | client_secret_basic                   |
    Then the response status is 201
    And the response has a non-empty "client_secret"
    And the response "token_endpoint_auth_method" is "client_secret_basic"

  Scenario: Registration rejects an unsupported grant type
    When the client submits a dynamic client registration request:
      | client_name    | acceptance-test-bad-grant       |
      | redirect_uris  | https://example.com/callback    |
      | grant_types    | not_a_real_grant_type           |
    Then the response status is 400
    And the response "error" is "invalid_client_metadata"

  Scenario: A client can read its own registration with its registration_access_token
    Given the client submits a dynamic client registration request:
      | client_name    | acceptance-test-readable   |
      | redirect_uris  | https://example.com/callback |
    When the client reads its own registration with its registration_access_token
    Then the response status is 200
    And the response "client_name" is "acceptance-test-readable"

  Scenario: Reading a registration without a token is rejected
    Given the client submits a dynamic client registration request:
      | client_name    | acceptance-test-noauth      |
      | redirect_uris  | https://example.com/callback |
    When the client reads its own registration without a token
    Then the response status is 401
    And the response "error" is "invalid_token"

  Scenario: Reading a registration with the wrong token 404s rather than 401 or 403
    Given the client submits a dynamic client registration request:
      | client_name    | acceptance-test-wrongtoken  |
      | redirect_uris  | https://example.com/callback |
    When the client reads its own registration with an incorrect token
    Then the response status is 404

  Scenario: A client can update its own registration
    Given the client submits a dynamic client registration request:
      | client_name    | acceptance-test-updatable   |
      | redirect_uris  | https://example.com/callback |
    When the client updates its own registration with its registration_access_token:
      | client_name    | acceptance-test-updated     |
      | redirect_uris  | https://example.com/callback |
    Then the response status is 200
    And the response "client_name" is "acceptance-test-updated"

  Scenario: A client can delete its own registration
    Given the client submits a dynamic client registration request:
      | client_name    | acceptance-test-deletable   |
      | redirect_uris  | https://example.com/callback |
    When the client deletes its own registration with its registration_access_token
    Then the response status is 204
    When the client reads its own registration with its registration_access_token
    Then the response status is 404
