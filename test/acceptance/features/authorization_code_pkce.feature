# RFC 6749 — The OAuth 2.0 Authorization Framework, §4.1
# https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
# The authorization_code grant: a client redirects the resource owner to
# the authorization server, the owner authenticates and consents, and
# the client exchanges a short-lived code for a token. This is the grant
# real end-user-facing applications use.
#
# RFC 7636 — Proof Key for Code Exchange (PKCE)
# https://datatracker.ietf.org/doc/html/rfc7636
# Prevents authorization-code interception attacks by requiring the
# client to present a verifier matching a challenge sent at the start of
# the flow.
#
# ADR-0009 — Authorization Code + PKCE
# docs/adr/0009-authorization-code-pkce.md
# This implementation makes S256 mandatory for every client (no "plain"
# fallback), enforces an exact redirect_uri match, and atomically
# consumes the code on exchange so replay is impossible.
#
# These scenarios bypass login-ui and identity-service: they call
# auth-server's bearer-authed POST /internal/issue-code directly, the
# same endpoint login-ui calls after a real sign-in (ADR-0011). That
# handoff mechanic — /oauth/authorize's redirect to login-ui, the actual
# sign-in, login-ui's call back to issue-code — is
# login_challenge_handoff.feature's job; this feature is about the
# authorization_code + PKCE grant contract itself.
@topology:auth-client-registry
Feature: Authorization Code Grant with PKCE

  Scenario: A full PKCE flow issues a valid token
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback" and scope "read"
    And the login_challenge is captured from the redirect
    And login-ui issues an authorization code for the login_challenge with consent "read"
    When the client exchanges the authorization code for a token
    Then the response status is 200
    And the response has a non-empty "access_token"
    And the response "scope" is "read"

  Scenario: An incorrect code_verifier is rejected
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback" and scope "read"
    And the login_challenge is captured from the redirect
    And login-ui issues an authorization code for the login_challenge with consent "read"
    When the client exchanges the authorization code for a token with an incorrect code_verifier
    Then the response status is 400
    And the response "error" is "invalid_grant"

  Scenario: Reusing an already-consumed authorization code is rejected
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback" and scope "read"
    And the login_challenge is captured from the redirect
    And login-ui issues an authorization code for the login_challenge with consent "read"
    And the client exchanges the authorization code for a token
    When the client exchanges the authorization code for a token
    Then the response status is 400
    And the response "error" is "invalid_grant"

  Scenario: An unregistered redirect_uri is rejected at the authorize endpoint
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    When the client starts an authorization_code flow with redirect_uri "https://attacker.example.com/callback" and scope "read"
    Then the response status is 400
    And the response "error" is "invalid_request"
