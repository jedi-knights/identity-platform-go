# RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)
# https://datatracker.ietf.org/doc/html/rfc9449
# Binds an access token to a key pair the client generates and never
# discloses: every request to the token endpoint must be accompanied by a
# `DPoP` header — a short-lived JWT, signed by the client's private key,
# proving the client currently holds that key. A stolen bearer token
# without the matching private key becomes useless.
#
# ADR-0025 — DPoP: Demonstrating Proof of Possession (RFC 9449)
# docs/adr/0025-dpop-proof-of-possession.md
# DPoP is optional, per-request — a client that never sends a `DPoP`
# header gets today's unchanged Bearer-token behavior. A client that
# sends a valid proof gets a `DPoP`-typed, key-bound token; the RFC 7638
# thumbprint of its key is echoed back as `cnf.jkt` on `/oauth/introspect`
# (never lifted onto the signed JWT itself — go-platform/jwtutil's Claims
# struct, an externally-versioned module this repo doesn't own, has no
# field for it). example-resource-service's RequireDPoPMiddleware (RFC
# 9449 §7.1 enforcement at the resource-server layer) is a real,
# unit-tested mechanism with no live cnf.jkt data source in the standard
# token-introspection-service topology today — see the ADR's Consequences
# section — so it is not exercised here; it is covered at the unit level
# in services/example-resource-service/internal/adapters/inbound/http/middleware_test.go.
Feature: DPoP — Demonstrating Proof of Possession

  @topology:auth-client-registry
  Scenario: A valid DPoP proof at the token endpoint yields a DPoP-typed, key-bound token
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    When the client requests a token using the client_credentials grant with scope "read" and a valid DPoP proof
    Then the response status is 200
    And the response "token_type" is "DPoP"
    And the "access_token" from the last response is captured as "access_token"
    And the client introspects the access_token
    Then the response status is 200
    And the response's cnf.jkt is non-empty

  @topology:auth-client-registry
  Scenario: A DPoP proof signed for the wrong endpoint is rejected
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    When the client requests a token using the client_credentials grant with scope "read" and a DPoP proof for the wrong endpoint
    Then the response status is 400
    And the response "error" is "invalid_dpop_proof"

  @topology:auth-client-registry
  Scenario: A token request with no DPoP header issues an ordinary Bearer token with no cnf claim
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    When the client requests a token using the client_credentials grant with scope "read"
    Then the response status is 200
    And the response "token_type" is "Bearer"
    And the "access_token" from the last response is captured as "access_token"
    And the client introspects the access_token
    Then the response status is 200
    And the response does not have a "cnf" field

  @topology:auth-metadata
  Scenario: The metadata document advertises the supported DPoP signing algorithms
    When the client sends a GET request to "/.well-known/oauth-authorization-server"
    Then the response status is 200
    And the response "dpop_signing_alg_values_supported" array contains "ES256"
    And the response "dpop_signing_alg_values_supported" array contains "RS256"
