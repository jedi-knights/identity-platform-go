# RFC 6749 — The OAuth 2.0 Authorization Framework, §4.4
# https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
# The client_credentials grant: a client authenticates with its own
# credentials (no end user involved) and receives an access token scoped
# to its own registered permissions. Used for machine-to-machine calls.
#
# RFC 9068 — JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens
# https://datatracker.ietf.org/doc/html/rfc9068
# Every grant type shares the same claim-building code path (see
# token_service.go), so this is the one place the profile's two headline
# requirements get checked directly against the issued JWT rather than
# just the token-response body: the `client_id` claim must identify the
# requesting client, and `scope` must be a single space-delimited string
# (§2.2.3.1) — never a JSON array, which is the mistake this profile
# exists to rule out.
#
# @topology:auth-client-registry tells the harness which service
# processes this feature needs (see steps/topology.go) — an intentional,
# narrow exception to "never use tags to control step behavior": this
# tag describes infrastructure requirements, not scenario assertions, and
# tags are the only signal godog's Before hook has available before any
# step runs.
@topology:auth-client-registry
Feature: Client Credentials Grant

  Scenario: A registered client obtains a token for one of its registered scopes
    Given a registered confidential OAuth client with scopes "read write" and grant type "client_credentials"
    When the client requests a token using the client_credentials grant with scope "read"
    Then the response status is 200
    And the response has a non-empty "access_token"
    And the response "token_type" is "Bearer"
    And the response "scope" is "read"
    And the response header "Cache-Control" is "no-store"

  Scenario: The issued access token is a JWT conforming to RFC 9068
    Given a registered confidential OAuth client with scopes "read write" and grant type "client_credentials"
    When the client requests a token using the client_credentials grant with scope "read write"
    And the "access_token" from the last response is captured as "access_token"
    Then the "access_token" JWT's "client_id" claim equals the captured "client_id"
    And the "access_token" JWT's "scope" claim equals "read write"

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
