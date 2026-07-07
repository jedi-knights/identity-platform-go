# RFC 7517 — JSON Web Key (JWK)
# https://datatracker.ietf.org/doc/html/rfc7517
# Defines the JWKS document shape published at /.well-known/jwks.json: a
# "keys" array of public-key representations, each carrying kty/use/alg/kid
# and the key-type-specific public parameters — for RSA, "n" and "e". A
# public JWK must never carry a private-key component.
#
# RFC 7518 — JSON Web Algorithms (JWA)
# https://datatracker.ietf.org/doc/html/rfc7518
# Defines "RS256" (§3.3) and its 2048-bit minimum key-size floor, which is
# what auth-server enforces on every configured signing key.
#
# ADR-0008 — RS256 + JWKS Token Signing
# docs/adr/0008-rs256-jwks-token-signing.md
# auth-server signs access tokens with RS256 by default and rotates keys
# through three fixed slots — current (signs new tokens), retiring/previous
# (still published for verifying tokens issued before rotation), and next
# (pre-staged, published ahead of promotion) — all three published
# simultaneously in the JWKS document during a rotation window. RFC 8725
# §3.1's algorithm-confusion defense means a verifier configured for RS256
# must reject an HS256-signed token outright, never fall back to treating
# it as valid.
Feature: JWKS Publication and Key Rotation

  @topology:auth-server-only
  Scenario: The JWKS endpoint exposes the current signing key without private material
    When the client fetches the JWKS document
    Then the response status is 200
    And the response header "Cache-Control" is "public, max-age=3600"
    And the JWKS document contains exactly 1 key
    And the JWKS document does not expose any private key material

  @topology:auth-client-registry
  Scenario: An issued access token's kid is published in the JWKS document
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "access_token"
    When the client fetches the JWKS document
    Then the access token's kid header is one of the JWKS document's key ids

  @topology:auth-server-rotating-keys
  Scenario: A rotation window publishes the current, retiring, and next keys in order
    When the client fetches the JWKS document
    Then the response status is 200
    And the JWKS document contains exactly 3 keys
    And the JWKS document's key ids are "current, retiring, next" in order

  @topology:auth-client-registry
  Scenario: An HS256-signed token is rejected by RS256 token introspection
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    When the client introspects a forged HS256-signed access token
    Then the response status is 200
    And the response "active" is false
