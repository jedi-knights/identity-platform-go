# Smoke tests — real docker-compose stack
#
# Unlike every scenario in ../features/*.feature (which spawn each
# service as a subprocess built directly from source), these scenarios
# run against the actual Docker images docker-compose.yml builds and
# wires together — validating the real Dockerfile, the real compose env
# wiring, and real container-to-container networking (e.g.
# AUTH_CLIENT_REGISTRY_URL resolving "client-registry-service" as a
# Docker network hostname), none of which the subprocess-based suite can
# exercise. Runs serially against one long-lived stack via `task
# test:smoke` — see main_test.go for why per-scenario isolation isn't
# needed here.
@smoke
Feature: Smoke tests against the real docker-compose stack

  Scenario Outline: Every service's real container is healthy
    Then <service> is healthy

    Examples:
      | service                      |
      | auth-server                  |
      | login-ui                     |
      | identity-service             |
      | client-registry-service      |
      | token-introspection-service  |
      | authorization-policy-service |
      | example-resource-service     |

  Scenario: The seeded test-client obtains a token from the real auth-server image
    When the seeded test-client requests a token using the client_credentials grant with scope "read"
    Then the response status is 200
    And the response has a non-empty "access_token"

  Scenario: A token issued by the real auth-server image introspects as active
    Given auth-server issues a token
    And the "access_token" from the last response is captured as "access_token"
    When the client introspects the access_token via auth-server
    Then the response status is 200
    And the response "active" is true

  Scenario: A revoked token introspects as inactive
    Given auth-server issues a token
    And the "access_token" from the last response is captured as "access_token"
    And the client revokes the access_token via auth-server
    When the client introspects the access_token via auth-server
    Then the response status is 200
    And the response "active" is false

  Scenario: The real auth-server image serves a JWKS document with an RS256 key
    When the client fetches auth-server's JWKS document
    Then the response status is 200
    And the response "keys" array is non-empty
    And at least one key in the "keys" array has "alg" "RS256"
