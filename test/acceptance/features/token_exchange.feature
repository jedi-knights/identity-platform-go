# RFC 8693 — OAuth 2.0 Token Exchange
# https://datatracker.ietf.org/doc/html/rfc8693
# A client presents a subject_token (and optionally an actor_token) and
# receives a new access token — the mechanism this platform uses for
# agent-to-agent (A2A) delegation: an agent acts on behalf of a subject
# while its own identity is preserved in the token's `act` claim, rather
# than impersonating the subject outright.
#
# ADR-0016 — Token Exchange (RFC 8693)
# docs/adr/0016-token-exchange-rfc-8693.md
# The exchanged token's `sub` is always the subject_token's subject —
# never the calling client's. The calling client (or, if present, the
# actor_token's principal) is recorded as the most recent hop in the
# `act` chain; every prior hop from the subject_token's own chain is
# preserved underneath it. The chain depth is capped (compiled-in
# default of 3 hops — the ADR names AUTH_MAX_DELEGATION_DEPTH as a
# configurable override, but no such env var actually exists in this
# codebase, so every deployment gets the same cap). Only the
# access_token URN is accepted for subject_token_type, actor_token_type,
# and requested_token_type — id_token and jwt are declared but always
# rejected.
@topology:auth-client-registry
Feature: Token Exchange

  Scenario: A token exchange issues a new access_token preserving the subject's identity
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials,urn:ietf:params:oauth:grant-type:token-exchange"
    And the client's registration is captured as "subject"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "subject_access_token"
    When the client exchanges the "subject_access_token" for a new access_token
    Then the response status is 200
    And the response "issued_token_type" is "urn:ietf:params:oauth:token-type:access_token"
    And the "access_token" from the last response is captured as "exchanged_access_token"
    And the "exchanged_access_token" JWT's "sub" claim equals the captured "subject_client_id"

  Scenario: A token exchange with an actor_token records the actor in the act claim
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials,urn:ietf:params:oauth:grant-type:token-exchange"
    And the client's registration is captured as "subject"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "subject_access_token"
    And a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    And the client's registration is captured as "actor"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "actor_access_token"
    When the client authenticating as "subject" exchanges "subject_access_token" using "actor_access_token" as actor
    Then the response status is 200
    And the "access_token" from the last response is captured as "exchanged_access_token"
    And the "exchanged_access_token" JWT's "sub" claim equals the captured "subject_client_id"
    And the "exchanged_access_token" JWT's "act.sub" claim equals the captured "actor_client_id"

  Scenario: Token exchange rejects an unsupported subject_token_type
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials,urn:ietf:params:oauth:grant-type:token-exchange"
    When the client exchanges a token with subject_token_type "urn:ietf:params:oauth:token-type:jwt"
    Then the response status is 400
    And the response "error" is "invalid_request"

  Scenario: Token exchange rejects an unsupported requested_token_type
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials,urn:ietf:params:oauth:grant-type:token-exchange"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "subject_access_token"
    When the client exchanges the "subject_access_token" requesting token type "urn:ietf:params:oauth:token-type:jwt"
    Then the response status is 400
    And the response "error" is "invalid_request"

  Scenario: Token exchange rejects a requested scope not present on the subject_token
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials,urn:ietf:params:oauth:grant-type:token-exchange"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "subject_access_token"
    When the client exchanges the "subject_access_token" for a new access_token with scope "write"
    Then the response status is 400
    And the response "error" is "invalid_request"

  Scenario: Token exchange enforces the maximum delegation depth
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials,urn:ietf:params:oauth:grant-type:token-exchange"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "subject_access_token"
    When the client exchanges the "subject_access_token" for a new access_token
    Then the response status is 200
    And the "access_token" from the last response is captured as "subject_access_token"
    When the client exchanges the "subject_access_token" for a new access_token
    Then the response status is 200
    And the "access_token" from the last response is captured as "subject_access_token"
    When the client exchanges the "subject_access_token" for a new access_token
    Then the response status is 200
    And the "access_token" from the last response is captured as "subject_access_token"
    When the client exchanges the "subject_access_token" for a new access_token
    Then the response status is 400
    And the response "error" is "invalid_request"

  Scenario: A public client may only exchange its own subject_token
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    And the client requests a token using the client_credentials grant with scope "read"
    And the "access_token" from the last response is captured as "subject_access_token"
    And a registered public OAuth client with grant type "urn:ietf:params:oauth:grant-type:token-exchange"
    When the client exchanges the "subject_access_token" for a new access_token
    Then the response status is 400
    And the response "error" is "unauthorized_client"
