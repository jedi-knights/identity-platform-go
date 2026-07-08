# ADR-0011 — Login-UI Service and the Login-Challenge Handoff
# docs/adr/0011-login-ui-service.md
# `/oauth/authorize` validates the request, persists a LoginChallenge,
# and 302s the user-agent to login-ui's sign-in page rather than
# authenticating the end user itself. login-ui runs the real sign-in
# against identity-service, then calls auth-server's bearer-authed
# POST /internal/issue-code to atomically redeem the challenge for an
# authorization code, and 302s the user-agent back to the relying
# party. The challenge is consumed exactly once — a second redemption
# attempt (replay), an unknown challenge ID, and an expired challenge
# all collapse to the same 400 invalid_request, deliberately: the
# caller cannot distinguish "never existed" from "already used" from
# "timed out" by the response alone.
#
# Every other feature file in this suite bypasses login-ui entirely —
# calling /internal/issue-code directly with a synthetic session_id —
# specifically because this handoff is its own concern, tested here.
# This feature file is the only one that runs the real login-ui binary
# and drives an actual POST to its /sign-in endpoint.
Feature: Login-Challenge Handoff

  @topology:auth-client-registry
  Scenario: Issuing a code for an unknown login_challenge is rejected
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    When login-ui issues an authorization code for login_challenge "totally-unknown-challenge-id" with consent "read"
    Then the response status is 400
    And the response "error" is "invalid_request"

  @topology:auth-client-registry
  Scenario: Issuing a code for an already-redeemed login_challenge is rejected
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback" and scope "read"
    And the login_challenge is captured from the redirect
    And login-ui issues an authorization code for the login_challenge with consent "read"
    When login-ui issues an authorization code for the login_challenge with consent "read"
    Then the response status is 400
    And the response "error" is "invalid_request"

  @topology:auth-client-registry-short-ttl
  Scenario: Issuing a code for an expired login_challenge is rejected
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback" and scope "read"
    And the login_challenge is captured from the redirect
    And 2 seconds pass
    When login-ui issues an authorization code for the login_challenge with consent "read"
    Then the response status is 400
    And the response "error" is "invalid_request"

  @topology:auth-client-registry
  Scenario: Issuing a code without a valid bearer token is rejected
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback" and scope "read"
    And the login_challenge is captured from the redirect
    When login-ui issues an authorization code for the login_challenge without a valid bearer token
    Then the response status is 401
    And the response "error" is "invalid_client"

  @topology:auth-client-registry
  Scenario: Issuing a code with consent broader than the challenge's requested scope is rejected
    Given a registered confidential OAuth client with scopes "read write", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback" and scope "read"
    And the login_challenge is captured from the redirect
    When login-ui issues an authorization code for the login_challenge with consent "write"
    Then the response status is 400
    And the response "error" is "invalid_request"

  @topology:login-challenge-handoff-e2e
  Scenario: A real sign-in through login-ui redeems the challenge and redirects back to the relying party
    Given a registered user in identity-service with email "handoff-e2e@example.com" and password "correct-horse-battery-staple"
    And a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback" and scope "read"
    And the login_challenge is captured from the redirect
    When the user signs in through login-ui with email "handoff-e2e@example.com" and password "correct-horse-battery-staple"
    Then the response status is 302
    And the redirect captures "code" and "state"
    And the client exchanges the authorization code for a token
    Then the response status is 200
    And the response has a non-empty "access_token"

  @topology:login-challenge-handoff-e2e
  Scenario: Signing in through login-ui with the wrong password does not redeem the challenge
    Given a registered user in identity-service with email "handoff-badpw@example.com" and password "correct-horse-battery-staple"
    And a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback" and scope "read"
    And the login_challenge is captured from the redirect
    When the user signs in through login-ui with email "handoff-badpw@example.com" and password "wrong-password"
    Then the response status is 200
    And the response body contains "invalid email or password"
