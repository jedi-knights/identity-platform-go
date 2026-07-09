# RFC 9126 — OAuth 2.0 Pushed Authorization Requests (PAR)
# https://datatracker.ietf.org/doc/html/rfc9126
# Lets a client POST its whole authorization request to a back-channel
# endpoint and get back a short-lived opaque request_uri, instead of
# putting every parameter in the front-channel /oauth/authorize query
# string (visible in browser history, Referer headers, and access logs).
#
# ADR-0021 — Pushed Authorization Requests
# docs/adr/0021-pushed-authorization-requests.md
# POST /oauth/par authenticates the client exactly like /oauth/token,
# runs the identical parameter validation /oauth/authorize runs, and
# returns {request_uri, expires_in}. /oauth/authorize then accepts
# request_uri + client_id in place of the full parameter set — the
# stored client_id must match, per RFC 9126 §4's anti-injection binding.
# This is additive: the existing direct-query-string flow is unchanged.
@topology:auth-client-registry
Feature: Pushed Authorization Requests

  Scenario: A pushed authorization request completes a full authorization_code flow
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    When the client pushes an authorization request with redirect_uri "https://example.com/callback" and scope "read"
    Then the response status is 201
    And the response has a non-empty "request_uri"
    And the "request_uri" from the last response is captured as "request_uri"
    When the client starts an authorization_code flow using the pushed request_uri
    Then the response status is 302
    And the login_challenge is captured from the redirect
    And login-ui issues an authorization code for the login_challenge with consent "read"
    And the client exchanges the authorization code for a token
    Then the response status is 200
    And the response has a non-empty "access_token"

  Scenario: Pushing an authorization request with an invalid client secret is rejected
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    When the client pushes an authorization request with client_secret "wrong-secret", redirect_uri "https://example.com/callback", and scope "read"
    Then the response status is 401
    And the response "error" is "invalid_client"

  Scenario: Pushing an authorization request without PKCE is rejected
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    When the client pushes an authorization request without a code_challenge, redirect_uri "https://example.com/callback", and scope "read"
    Then the response status is 400
    And the response "error" is "invalid_request"

  Scenario: An unknown request_uri is rejected at the authorize endpoint
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    When the client starts an authorization_code flow using request_uri "urn:ietf:params:oauth:request_uri:does-not-exist"
    Then the response status is 400
    And the response "error" is "invalid_request"

  Scenario: A request_uri presented with a different client_id is rejected
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client pushes an authorization request with redirect_uri "https://example.com/callback" and scope "read"
    And the "request_uri" from the last response is captured as "request_uri"
    And a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://other.example.com/callback"
    When the client starts an authorization_code flow using the pushed request_uri
    Then the response status is 400
    And the response "error" is "invalid_request"

  @topology:auth-metadata
  Scenario: The metadata document advertises the pushed_authorization_request_endpoint
    When the client sends a GET request to "/.well-known/oauth-authorization-server"
    Then the response status is 200
    And the response has a non-empty "pushed_authorization_request_endpoint"
