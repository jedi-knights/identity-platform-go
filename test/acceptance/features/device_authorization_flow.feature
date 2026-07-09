# RFC 8628 — OAuth 2.0 Device Authorization Grant
# docs/adr/0022-device-authorization-flow.md
# A device with no redirect-capable browser (a CLI, an IoT device) calls
# POST /device_authorization to obtain a device_code (which it polls with)
# and a short user_code (which it displays to the user). The user visits
# login-ui's verification page on a separate, browser-capable device,
# signs in, and approves or denies the request. The device's poll against
# /oauth/token then either receives a token pair or one of RFC 8628 §3.5's
# poll-in-progress errors: authorization_pending, access_denied, or
# expired_token. slow_down is out of scope per ADR-0022.
Feature: Device Authorization Flow

  @topology:auth-client-registry
  Scenario: Requesting device authorization returns a device_code and user_code
    Given a registered confidential OAuth client with scopes "read" and grant type "urn:ietf:params:oauth:grant-type:device_code"
    When the client requests device authorization with scope "read"
    Then the response status is 200
    And the response has a non-empty "device_code"
    And the response has a non-empty "user_code"
    And the response has a non-empty "verification_uri"
    And the response has a non-empty "verification_uri_complete"

  @topology:auth-client-registry
  Scenario: A public client can request device authorization without a client_secret
    Given a registered public OAuth client with grant type "urn:ietf:params:oauth:grant-type:device_code"
    When the client requests device authorization with scope "read"
    Then the response status is 200
    And the response has a non-empty "device_code"

  @topology:auth-client-registry
  Scenario: Requesting device authorization for a client without the device_code grant is rejected
    Given a registered confidential OAuth client with scopes "read" and grant type "client_credentials"
    When the client requests device authorization with scope "read"
    Then the response status is 400
    And the response "error" is "unauthorized_client"

  @topology:auth-client-registry
  Scenario: Polling before the user has approved returns authorization_pending
    Given a registered confidential OAuth client with scopes "read" and grant type "urn:ietf:params:oauth:grant-type:device_code"
    And the client requests device authorization with scope "read"
    When the device polls the token endpoint with the device_code
    Then the response status is 400
    And the response "error" is "authorization_pending"

  @topology:auth-client-registry
  Scenario: Polling with an unknown device_code returns expired_token
    Given a registered confidential OAuth client with scopes "read" and grant type "urn:ietf:params:oauth:grant-type:device_code"
    When the device polls the token endpoint with device_code "never-issued-device-code"
    Then the response status is 400
    And the response "error" is "expired_token"

  @topology:login-challenge-handoff-e2e
  Scenario: A user approves a device authorization request through login-ui and the device's poll succeeds
    Given a registered user in identity-service with email "device-approve@example.com" and password "correct-horse-battery-staple"
    And a registered confidential OAuth client with scopes "read" and grant type "urn:ietf:params:oauth:grant-type:device_code"
    And the client requests device authorization with scope "read"
    When the user approves the device authorization on the verification page with email "device-approve@example.com" and password "correct-horse-battery-staple"
    And the device polls the token endpoint with the device_code
    Then the response status is 200
    And the response has a non-empty "access_token"

  @topology:login-challenge-handoff-e2e
  Scenario: A user denies a device authorization request and the device's poll receives access_denied
    Given a registered user in identity-service with email "device-deny@example.com" and password "correct-horse-battery-staple"
    And a registered confidential OAuth client with scopes "read" and grant type "urn:ietf:params:oauth:grant-type:device_code"
    And the client requests device authorization with scope "read"
    When the user denies the device authorization on the verification page
    And the device polls the token endpoint with the device_code
    Then the response status is 400
    And the response "error" is "access_denied"

  @topology:login-challenge-handoff-e2e
  Scenario: A device_code cannot be redeemed twice
    Given a registered user in identity-service with email "device-replay@example.com" and password "correct-horse-battery-staple"
    And a registered confidential OAuth client with scopes "read" and grant type "urn:ietf:params:oauth:grant-type:device_code"
    And the client requests device authorization with scope "read"
    And the user approves the device authorization on the verification page with email "device-replay@example.com" and password "correct-horse-battery-staple"
    And the device polls the token endpoint with the device_code
    When the device polls the token endpoint with the device_code
    Then the response status is 400
    And the response "error" is "expired_token"
