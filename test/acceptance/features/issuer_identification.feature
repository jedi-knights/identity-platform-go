# RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification
# https://datatracker.ietf.org/doc/html/rfc9207
# Every authorization response — success or error — carries an `iss`
# parameter naming the issuing authorization server, so a client talking
# to more than one AS can detect a mix-up attack (a code or error from
# AS-1 sent back to AS-2). This platform has one issuer today, but the
# response shape is exercised in full regardless.
#
# ADR-0020 — Authorization Server Issuer Identification
# docs/adr/0020-authorization-server-issuer-identification.md
# The authorization response is split across two services here: an early
# parameter error is redirected to the client directly by auth-server;
# the success response is redirected by login-ui after the real
# login-challenge handoff (ADR-0011). Both paths carry `iss`.
Feature: Authorization Server Issuer Identification

  @topology:auth-client-registry
  Scenario: An authorize-time parameter error redirect includes the issuer
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    When the client starts an authorization_code flow with redirect_uri "https://example.com/callback" and scope "admin"
    Then the response status is 302
    And the redirect Location's "error" query parameter is "invalid_scope"
    And the redirect Location's "iss" query parameter is "identity-platform"

  @topology:login-challenge-handoff-e2e
  Scenario: A real sign-in's redirect back to the relying party includes the issuer
    Given a registered user in identity-service with email "iss-e2e@example.com" and password "correct-horse-battery-staple"
    And a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback" and scope "read"
    And the login_challenge is captured from the redirect
    When the user signs in through login-ui with email "iss-e2e@example.com" and password "correct-horse-battery-staple"
    Then the response status is 302
    And the redirect captures "code" and "state"
    And the redirect Location's "iss" query parameter is "identity-platform"
