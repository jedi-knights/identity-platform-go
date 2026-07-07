# RFC 6749 — The OAuth 2.0 Authorization Framework, §4.4
# https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
# The client_credentials grant: a client authenticates with its own
# credentials (no end user involved) and receives an access token scoped
# to its own registered permissions. Used for machine-to-machine calls.
Feature: Client Credentials Grant

  Scenario: A registered client obtains a token for one of its registered scopes
    Given a registered confidential OAuth client with scopes "read write" and grant type "client_credentials"
    When the client requests a token using the client_credentials grant with scope "read"
    Then the response status is 200
    And the response has a non-empty "access_token"
    And the response "token_type" is "Bearer"
    And the response "scope" is "read"
    And the response header "Cache-Control" is "no-store"

  Scenario: An invalid client secret is rejected
    Given a registered confidential OAuth client with scopes "read write" and grant type "client_credentials"
    When the client requests a token using the client_credentials grant with client_secret "wrong-secret" and scope "read"
    Then the response status is 401
    And the response "error" is "invalid_client"

  Scenario: A scope outside the client's registered scopes is rejected
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    When the client requests a token using the client_credentials grant with scope "admin"
    Then the response status is 400
    And the response "error" is "invalid_scope"
