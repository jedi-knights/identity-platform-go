# RFC 7662 — OAuth 2.0 Token Introspection
# https://datatracker.ietf.org/doc/html/rfc7662
# Lets a resource server ask the authorization server (or, here, a
# dedicated introspection service validating tokens the authorization
# server issued) whether a presented token is currently active, and
# retrieve its metadata.
#
# Key invariant (§2.2): introspection always returns HTTP 200, even for
# invalid, expired, or malformed tokens — an invalid token must produce
# {"active": false}, never a 4xx. A non-200 response can be misread by a
# resource server as a transient error and allowed through.
@topology:auth-client-registry-introspection
Feature: Token Introspection

  Scenario: A valid access token introspects as active with its metadata
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "access_token"
    When a resource server introspects the access_token via token-introspection-service
    Then the response status is 200
    And the response "active" is true
    And the response "scope" is "read"

  Scenario: A malformed token introspects as inactive, never as an error
    When a resource server introspects "not-a-real-jwt" via token-introspection-service
    Then the response status is 200
    And the response "active" is false

  Scenario: Introspection without a valid pre-shared secret is rejected
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "access_token"
    When a resource server introspects the access_token via token-introspection-service without a valid secret
    Then the response status is 401
    And the response "error" is "invalid_client"
