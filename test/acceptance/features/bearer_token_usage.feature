# RFC 6750 — The OAuth 2.0 Authorization Framework: Bearer Token Usage
# https://datatracker.ietf.org/doc/html/rfc6750
# Governs how a client presents an access token to a resource server
# (the "Authorization: Bearer <token>" header) and how the resource
# server signals authentication/authorization failures back — missing
# or malformed credentials get a bare WWW-Authenticate challenge (§3),
# insufficient scope gets one carrying error="insufficient_scope" (§3.1).
@topology:auth-client-registry-resource
Feature: Bearer Token Usage

  Scenario: A valid token with sufficient scope is accepted
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "access_token"
    When the client calls "GET /resources" on example-resource-service with the access_token
    Then the response status is 200

  Scenario: A missing Authorization header is rejected
    When the client calls "GET /resources" on example-resource-service without an Authorization header
    Then the response status is 401
    And the response header "WWW-Authenticate" is "Bearer realm="example-resource-service""

  Scenario: A malformed Authorization header is rejected
    When the client calls "GET /resources" on example-resource-service with a malformed Authorization header
    Then the response status is 401
    And the response header "WWW-Authenticate" is "Bearer realm="example-resource-service""

  Scenario: Insufficient scope is rejected with error="insufficient_scope"
    Given a registered confidential OAuth client with scopes "write" and grant type "client_credentials"
    And the client requests a token using the client_credentials grant with scope "write"
    And the "access_token" from the last response is captured as "access_token"
    When the client calls "GET /resources" on example-resource-service with the access_token
    Then the response status is 403
    And the response "code" is "FORBIDDEN"
    And the response header "WWW-Authenticate" is "Bearer realm="example-resource-service", error="insufficient_scope", scope="read""
