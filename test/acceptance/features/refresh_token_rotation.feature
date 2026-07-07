# RFC 6749 — The OAuth 2.0 Authorization Framework, §6
# https://datatracker.ietf.org/doc/html/rfc6749#section-6
# Refreshing an access token: a client presents a refresh token to obtain
# a new access token without involving the resource owner again. This
# repo intentionally deviates from §4.4.3's "SHOULD NOT" and issues
# refresh tokens on client_credentials too, to make the full token
# lifecycle testable (see services/auth-server/internal/domain/token.go).
#
# ADR-0014 — Refresh Token Rotation & Replay Detection
# docs/adr/0014-refresh-token-rotation-replay.md
# On every use, the old refresh token is deleted and a new one is issued
# (rotation). Presenting an already-used (rotated-away) refresh token is
# replay and must be rejected.
@topology:auth-client-registry
Feature: Refresh Token Rotation

  Scenario: A refresh token is exchanged for a new access token and rotates
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials,refresh_token"
    And the client obtains a token using the client_credentials grant with scope "read"
    When the client requests a token using the refresh_token grant
    Then the response status is 200
    And the response has a non-empty "access_token"
    And the response has a non-empty "refresh_token"

  Scenario: A rotated-away refresh token is rejected on replay
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials,refresh_token"
    And the client obtains a token using the client_credentials grant with scope "read"
    And the current refresh_token is set aside for a later replay attempt
    And the client requests a token using the refresh_token grant
    When the client requests a token using the refresh_token grant with the previous refresh_token again
    Then the response status is 401
    And the response "error" is "invalid_client"

  Scenario: An unknown refresh token is rejected
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials,refresh_token"
    When the client requests a token using the refresh_token grant with refresh_token "not-a-real-token"
    Then the response status is 401
    And the response "error" is "invalid_client"
