# OpenID Connect Core 1.0
# https://openid.net/specs/openid-connect-core-1_0.html
# Layers end-user identity assertion on top of OAuth 2.0. A client that
# includes the "openid" scope in an authorization_code request receives,
# alongside the access token, a signed id_token asserting who
# authenticated — plus a nonce round-trip for replay protection and a
# /userinfo endpoint the access token itself can be used to query for
# the same claims.
#
# ADR-0010 — OIDC Core
# docs/adr/0010-oidc-core.md
# This implementation issues id_token only from the authorization_code
# grant (never client_credentials, which has no end user to assert an
# identity for), copies the nonce straight through from /oauth/authorize
# to the id_token without server-side validation, and serves /userinfo
# from auth-server rather than identity-service since the endpoint is
# OAuth-protocol-aware (bearer auth, scope-gated claim projection).
#
# Scenarios tag their own topology rather than sharing one Feature-level
# tag — most need auth-server + client-registry-service with OIDC enabled
# but no identity-service (so /userinfo's claims fetcher stays nil); the
# last scenario additionally needs identity-service running, so it carries
# a different topology tag.
Feature: OpenID Connect Core

  @topology:auth-client-registry-oidc
  Scenario: An authorization_code grant with openid scope issues an id_token
    Given a registered confidential OAuth client with scopes "openid", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback", scope "openid", and nonce "test-nonce-abc"
    And the login_challenge is captured from the redirect
    And login-ui issues an authorization code for the login_challenge for subject "user-42" with consent "openid"
    When the client exchanges the authorization code for a token
    Then the response status is 200
    And the response has a non-empty "id_token"
    And the "id_token" from the last response is captured as "id_token"
    And the id_token's "sub" claim is "user-42"

  @topology:auth-client-registry-oidc
  Scenario: The nonce supplied at authorization is echoed in the id_token
    Given a registered confidential OAuth client with scopes "openid", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback", scope "openid", and nonce "test-nonce-xyz"
    And the login_challenge is captured from the redirect
    And login-ui issues an authorization code for the login_challenge for subject "user-7" with consent "openid"
    And the client exchanges the authorization code for a token
    And the "id_token" from the last response is captured as "id_token"
    Then the id_token's "nonce" claim is "test-nonce-xyz"

  @topology:auth-client-registry-oidc
  Scenario: A client_credentials grant never issues an id_token even with openid scope
    Given a registered confidential OAuth client with scopes "openid read" and grant type "client_credentials"
    When the client requests a token using the client_credentials grant with scope "openid read"
    Then the response status is 200
    And the response does not have a "id_token" field

  @topology:auth-client-registry-oidc
  Scenario: /userinfo rejects a request with no access token
    When the client calls /userinfo without an access_token
    Then the response status is 401

  @topology:auth-client-registry-oidc
  Scenario: /userinfo rejects a token that lacks the openid scope
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "access_token"
    When the client calls /userinfo with the access_token
    Then the response status is 403

  @topology:auth-client-registry-oidc
  Scenario: /userinfo returns 503 when no identity-service backend is configured
    Given a registered confidential OAuth client with scopes "openid", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback", scope "openid", and nonce "n"
    And the login_challenge is captured from the redirect
    And login-ui issues an authorization code for the login_challenge for subject "user-503" with consent "openid"
    And the client exchanges the authorization code for a token
    And the "access_token" from the last response is captured as "access_token"
    When the client calls /userinfo with the access_token
    Then the response status is 503

  @topology:auth-client-registry-identity-oidc
  Scenario: /userinfo returns the registered user's claims when identity-service is configured
    Given a registered user in identity-service with email "oidc-e2e@example.com" and name "OIDC E2E"
    And a registered confidential OAuth client with scopes "openid email profile", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback", scope "openid email profile", and nonce "n"
    And the login_challenge is captured from the redirect
    And login-ui issues an authorization code for the login_challenge for the registered user with consent "openid email profile"
    And the client exchanges the authorization code for a token
    And the "access_token" from the last response is captured as "access_token"
    When the client calls /userinfo with the access_token
    Then the response status is 200
    And the response "email" is "oidc-e2e@example.com"
