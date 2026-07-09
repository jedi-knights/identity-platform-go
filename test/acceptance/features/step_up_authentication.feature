# RFC 9470 — OAuth 2.0 Step Up Authentication Challenge Protocol
# https://datatracker.ietf.org/doc/html/rfc9470
# Lets a client tell the authorization server what authentication
# context it needs (`acr_values` on /oauth/authorize) and lets a
# resource server signal that a token's authentication context is
# insufficient (`WWW-Authenticate: error="insufficient_user_authentication"`).
#
# ADR-0024 — Step-Up Authentication Challenge (RFC 9470)
# docs/adr/0024-step-up-authentication-challenge.md
# This platform has exactly one authentication method (email + password)
# and no persistent login-ui session — every authorization_code
# redemption re-authenticates the user from scratch. There is no
# session state for acr_values to *elevate*: any authorization_code
# flow already performs a fresh, interactive login, so the platform-
# wide constant "pwd" is stamped on every token an authorization_code
# redemption issues, regardless of what acr_values was requested.
# `acr_values` is parsed and stored for protocol completeness (and
# advertised via `acr_values_supported` in metadata) but does not
# branch login-ui's behavior — there is only one method to satisfy it
# with. The satisfied value is only visible to a caller of auth-
# server's own /oauth/introspect — it is deliberately not lifted onto
# the signed JWT, since go-platform/jwtutil's Claims struct (an
# externally-versioned module this repo does not own) has no field for
# it. This feature file exercises the fully real, end-to-end part of
# that round trip: /oauth/authorize with acr_values, a real login-ui
# sign-in, and the issued token's acr echoed back by introspection.
# example-resource-service's RequireACRMiddleware (RFC 9470 enforcement
# at the resource-server layer) is a real, unit-tested mechanism with
# no live data source in the standard token-introspection-service
# topology today — see the ADR's Consequences section — so it is not
# exercised here; it is covered at the unit level in
# services/example-resource-service/internal/adapters/inbound/http/middleware_test.go.
Feature: Step-Up Authentication Challenge

  @topology:login-challenge-handoff-e2e
  Scenario: A real sign-in through login-ui yields a token whose introspection echoes the satisfied acr
    Given a registered user in identity-service with email "stepup-e2e@example.com" and password "correct-horse-battery-staple"
    And a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback", scope "read", and acr_values "pwd"
    And the login_challenge is captured from the redirect
    When the user signs in through login-ui with email "stepup-e2e@example.com" and password "correct-horse-battery-staple"
    Then the response status is 302
    And the redirect captures "code" and "state"
    And the client exchanges the authorization code for a token
    Then the response status is 200
    And the "access_token" from the last response is captured as "access_token"
    And the client introspects the access_token
    Then the response status is 200
    And the response "acr" is "pwd"

  @topology:login-challenge-handoff-e2e
  Scenario: The satisfied acr is stamped even when the client requested a different acr_values
    Given a registered user in identity-service with email "stepup-mismatch@example.com" and password "correct-horse-battery-staple"
    And a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    And the client starts an authorization_code flow with redirect_uri "https://example.com/callback", scope "read", and acr_values "urn:example:mfa"
    And the login_challenge is captured from the redirect
    When the user signs in through login-ui with email "stepup-mismatch@example.com" and password "correct-horse-battery-staple"
    Then the response status is 302
    And the redirect captures "code" and "state"
    And the client exchanges the authorization code for a token
    Then the response status is 200
    And the "access_token" from the last response is captured as "access_token"
    And the client introspects the access_token
    Then the response status is 200
    And the response "acr" is "pwd"

  @topology:auth-metadata-full
  Scenario: The metadata document advertises the supported acr_values
    When the client sends a GET request to "/.well-known/openid-configuration"
    Then the response status is 200
    And the response "acr_values_supported" array contains "pwd"
