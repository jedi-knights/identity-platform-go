# RFC 8414 — OAuth 2.0 Authorization Server Metadata
# https://datatracker.ietf.org/doc/html/rfc8414
# A well-known, unauthenticated document at
# /.well-known/oauth-authorization-server letting a client discover every
# endpoint and capability of this authorization server (endpoint URLs,
# supported grant types, scopes, PKCE methods, auth methods) without
# hardcoding them.
#
# OpenID Connect Discovery 1.0
# https://openid.net/specs/openid-connect-discovery-1_0.html
# The OIDC analogue at /.well-known/openid-configuration — a superset of
# the RFC 8414 document that adds OIDC-only fields (userinfo_endpoint,
# end_session_endpoint, subject_types_supported, ...) when this platform's
# OIDC mode is active.
#
# ADR-0012 — Authorization Server Metadata
# docs/adr/0012-authorization-server-metadata.md
# Both documents are derived live from running config rather than a
# hand-authored file, so a route that isn't wired up can't be advertised
# by mistake. Metadata is disabled entirely (both endpoints 404) when
# AUTH_METADATA_PUBLIC_BASE_URL is unset, since every endpoint URL in the
# document must be an absolute URL built from it.
Feature: Authorization Server Metadata

  @topology:auth-metadata
  Scenario: The RFC 8414 metadata document exposes core OAuth endpoints
    When the client sends a GET request to "/.well-known/oauth-authorization-server"
    Then the response status is 200
    And the response header "Cache-Control" is "public, max-age=3600"
    And the response has a non-empty "issuer"
    And the response has a non-empty "authorization_endpoint"
    And the response has a non-empty "token_endpoint"
    And the response has a non-empty "jwks_uri"
    And the response "response_types_supported" array contains "code"

  @topology:auth-metadata
  Scenario: The RFC 8414 metadata document omits OIDC-only fields when OIDC is disabled
    When the client sends a GET request to "/.well-known/oauth-authorization-server"
    Then the response status is 200
    And the response does not have a "userinfo_endpoint" field

  @topology:auth-metadata-full
  Scenario: The OIDC discovery document includes userinfo_endpoint and end_session_endpoint when OIDC is enabled
    When the client sends a GET request to "/.well-known/openid-configuration"
    Then the response status is 200
    And the response has a non-empty "userinfo_endpoint"
    And the response has a non-empty "end_session_endpoint"

  @topology:auth-metadata-full
  Scenario: The metadata document includes the configured registration_endpoint
    When the client sends a GET request to "/.well-known/oauth-authorization-server"
    Then the response "registration_endpoint" is "https://clients.example.com/register"

  @topology:auth-client-registry
  Scenario Outline: Metadata endpoints are not registered when no public base URL is configured
    When the client sends a GET request to "<path>"
    Then the response status is 404

    Examples:
      | path                                     |
      | /.well-known/oauth-authorization-server   |
      | /.well-known/openid-configuration          |
