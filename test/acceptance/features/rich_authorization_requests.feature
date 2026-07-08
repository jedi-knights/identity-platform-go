# RFC 9396 — OAuth 2.0 Rich Authorization Requests
# https://datatracker.ietf.org/doc/html/rfc9396
# Lets a client request fine-grained permissions via a structured
# `authorization_details` array instead of coarse scope strings — each
# element carries a `type` discriminator and type-specific fields. This
# platform registers two types: `mcp_tool` (permission to invoke a
# specific MCP tool) and `resource` (permission scoped to specific
# locations/actions/datatypes).
#
# ADR-0017 — Rich Authorization Requests (RFC 9396)
# docs/adr/0017-rich-authorization-requests-rfc-9396.md
# `authorization_details` is accepted on both /oauth/authorize (query
# param) and /oauth/token (form param, all grants). A malformed or
# invalid value at /oauth/authorize redirects back to the client with
# `?error=invalid_authorization_details` (RFC 6749 §4.1.2.1 routing,
# same as every other authorize-time validation failure); the same
# failure at /oauth/token returns a 400 JSON body instead, since there's
# no redirect target at that endpoint. Granted details are embedded in
# the issued access token's `authorization_details` claim and echoed by
# introspection. Token exchange (ADR-0016) narrows the subject_token's
# details to any type the caller requests — but rejects a requested
# type that isn't present on the subject_token with `invalid_request`,
# not `invalid_authorization_details`, since that failure is a token-
# exchange-specific authorization rule, not a wire-format problem.
#
# Scenarios tag their own topology rather than sharing one Feature-level
# tag — most need auth-server + client-registry-service; the metadata
# scenario needs the separate auth-metadata topology instead.
Feature: Rich Authorization Requests

  @topology:auth-client-registry
  Scenario: A client_credentials grant with a valid mcp_tool detail embeds it in the token
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    When the client requests a token using the client_credentials grant with scope "read" and authorization_details:
      """
      [{"type": "mcp_tool", "tool": "search"}]
      """
    Then the response status is 200
    And the "access_token" from the last response is captured as "access_token"
    And the client introspects the access_token
    Then the response status is 200
    And the response's authorization_details contains a "mcp_tool" entry with "tool" equal to "search"

  @topology:auth-client-registry
  Scenario: A client_credentials grant rejects malformed authorization_details JSON
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    When the client requests a token using the client_credentials grant with scope "read" and authorization_details:
      """
      not valid json
      """
    Then the response status is 400
    And the response "error" is "invalid_authorization_details"

  @topology:auth-client-registry
  Scenario: A client_credentials grant rejects an unknown authorization_details type
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    When the client requests a token using the client_credentials grant with scope "read" and authorization_details:
      """
      [{"type": "payment"}]
      """
    Then the response status is 400
    And the response "error" is "invalid_authorization_details"

  @topology:auth-client-registry
  Scenario: A client_credentials grant rejects an mcp_tool detail missing the required tool field
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    When the client requests a token using the client_credentials grant with scope "read" and authorization_details:
      """
      [{"type": "mcp_tool"}]
      """
    Then the response status is 400
    And the response "error" is "invalid_authorization_details"

  @topology:auth-client-registry
  Scenario: A client_credentials grant rejects a resource detail with none of locations, actions, or datatypes
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    When the client requests a token using the client_credentials grant with scope "read" and authorization_details:
      """
      [{"type": "resource"}]
      """
    Then the response status is 400
    And the response "error" is "invalid_authorization_details"

  @topology:auth-client-registry
  Scenario: An authorization_code grant persists authorization_details from /oauth/authorize through to the issued token
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    When the client starts an authorization_code flow with redirect_uri "https://example.com/callback", scope "read", and authorization_details:
      """
      [{"type": "resource", "locations": ["https://api.example.com"]}]
      """
    And the login_challenge is captured from the redirect
    And login-ui issues an authorization code for the login_challenge with consent "read"
    And the client exchanges the authorization code for a token
    Then the response status is 200
    And the "access_token" from the last response is captured as "access_token"
    And the client introspects the access_token
    Then the response status is 200
    And the response's authorization_details contains a "resource" entry with "locations" equal to "[https://api.example.com]"

  @topology:auth-client-registry
  Scenario: /oauth/authorize rejects malformed authorization_details by redirecting with an error
    Given a registered confidential OAuth client with scopes "read", grant type "authorization_code", and redirect_uri "https://example.com/callback"
    And the client generates a PKCE code_verifier and code_challenge
    When the client starts an authorization_code flow with redirect_uri "https://example.com/callback", scope "read", and authorization_details:
      """
      not valid json
      """
    Then the response status is 302
    And the response redirects with error "invalid_authorization_details"

  @topology:auth-metadata
  Scenario: The metadata document advertises the supported authorization_details types
    When the client sends a GET request to "/.well-known/oauth-authorization-server"
    Then the response status is 200
    And the response "authorization_details_types_supported" array contains "mcp_tool"
    And the response "authorization_details_types_supported" array contains "resource"

  @topology:auth-client-registry
  Scenario: Token exchange rejects an authorization_details type not present on the subject_token
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials,urn:ietf:params:oauth:grant-type:token-exchange"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "subject_access_token"
    When the client exchanges the "subject_access_token" for a new access_token with authorization_details:
      """
      [{"type": "mcp_tool", "tool": "search"}]
      """
    Then the response status is 400
    And the response "error" is "invalid_request"
