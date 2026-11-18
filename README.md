# Identity Platform Go

A reference OAuth 2.0 / OpenID Connect platform in Go: eight small services you can run on a laptop and read in an afternoon each.

![CI](https://github.com/jedi-knights/identity-platform-go/actions/workflows/ci.yml/badge.svg)
![Deploy](https://github.com/jedi-knights/identity-platform-go/actions/workflows/deploy.yml/badge.svg)
![Release](https://github.com/jedi-knights/identity-platform-go/actions/workflows/release.yml/badge.svg)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#requirements">Requirements</a> ·
  <a href="#installation">Installation</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#examples">Examples</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#api-reference">API Reference</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#deployment-flyio">Deployment</a> ·
  <a href="#horizontal-scalability">Scalability</a> ·
  <a href="#development">Development</a> ·
  <a href="#release-process">Releases</a> ·
  <a href="#contributing">Contributing</a>
</p>

---

## Overview

If you have integrated an app with Auth0, Keycloak or Okta, you have used a token endpoint, a JWKS URL and an introspection endpoint, but they were black boxes. This repository is those parts, split into services you can start locally: an authorization server (`auth-server`), a user store (`identity-service`), a client registry, a token introspector, a policy engine, a sign-in UI (`login-ui`), an entitlements service and a protected example API.

Most tutorial servers issue one kind of token and stop: no revocation, no PKCE, no key rotation, secrets compared with `==`. Full products are too large to learn from. This platform sits between: small enough to read, complete enough that the hard parts are present and explained in [Architecture Decision Records](docs/adr/).

Doing OAuth properly by hand means getting a lot of fiddly things right at once:

- PKCE with `S256` mandatory, and `plain` rejected, so public clients are safe.
- RS256 signing with a published JWKS and a key-rotation window (`previous`, `current`, `next`), not a shared secret.
- Introspection that answers `200 {"active": false}` for bad tokens, and revocation that is idempotent.
- `Cache-Control: no-store` on every token response, and constant-time secret comparison.
- Scopes limited to what the client is registered for.
- Refresh-token rotation with replay detection.
- A login hand-off between the authorization server and the UI that shares no session state.
- Stateless services that run as two or more replicas with no single point of failure.

Here is the smallest complete example: start the authorization server with a development client, then ask for a token.

```bash
AUTH_DEV_SEED_CLIENTS=true AUTH_DEV_CLIENT_SECRET=dev-secret task run:auth-server &

curl -s -X POST http://localhost:8080/oauth/token \
  -d grant_type=client_credentials -d client_id=dev-client \
  -d client_secret=dev-secret -d scope=read
```

```json
{"access_token":"eyJhbGciOiJSUzI1NiIs...","token_type":"Bearer","expires_in":300,"scope":"read","refresh_token":"11972ee0ed48548809d0214fc858ca17"}
```

That one request bought you:

| You get | Where to see it |
|---------|-----------------|
| An RS256 JWT whose header carries a `kid` (`"typ":"at+jwt"`, per RFC 9068) | Decode the first segment of `access_token` |
| The matching public key | `GET /.well-known/jwks.json` lists the same `kid` |
| A token you can introspect and revoke | [Examples](#examples) |
| A scope limited to what `dev-client` may have | Ask for `admin` and get `invalid_scope` |
| `Cache-Control: no-store` and `Pragma: no-cache` | `curl -i` the same request |

---

## Features

- OAuth 2.0 grants: `client_credentials`, `refresh_token`, `authorization_code` with mandatory PKCE, device authorization, token exchange, JWT-bearer and SAML-bearer assertions.
- OpenID Connect Core: ID tokens, `/userinfo`, discovery metadata, and JWKS.
- Token introspection, revocation, DPoP proof of possession, pushed authorization requests and rich authorization requests.
- A sign-in UI with sign-up, email verification, password reset (delivered by SMTP), device approval and billing screens.
- Dynamic client registration and RBAC policy evaluation.
- Hexagonal architecture in every service, with the dependency direction enforced by convention and documented in ADRs.
- In-memory storage for zero-dependency local runs; Redis and PostgreSQL adapters for production.
- Deployed to Fly.io as private apps, with a Docker Compose stack for local use.

The full RFC coverage table lives in [`CLAUDE.md`](CLAUDE.md).

---

## Requirements

- **Go 1.26+** (see `go.work`)
- **[Task](https://taskfile.dev/)** to run the build, test and lint commands
- **[jq](https://jqlang.github.io/jq/)** for the `curl` examples that parse JSON
- **[Docker](https://docs.docker.com/get-docker/)** with the Compose plugin, only for the full stack, the acceptance suite and the smoke tests
- **[golangci-lint](https://golangci-lint.run/) v2.15.0** for `task lint` (the version CI pins)
- **[swag](https://github.com/swaggo/swag)**, only for `task swagger`
- The [Allure](https://allurereport.org/) command line, only to view acceptance results as an HTML report

---

## Installation

```bash
git clone https://github.com/jedi-knights/identity-platform-go.git
cd identity-platform-go
task build        # builds the six core services into bin/
```

`task build` covers `auth-server`, `identity-service`, `client-registry-service`, `token-introspection-service`, `authorization-policy-service` and `example-resource-service`. `login-ui` and `entitlements-service` are built with `go build ./cmd` from their own directories.

### Run one service

```bash
task run:auth-server
task run:identity-service
task run:client-registry-service
task run:token-introspection-service
task run:authorization-policy-service
task run:example-resource-service

# login-ui and entitlements-service have no task; run them from their module:
cd services/login-ui && go run ./cmd
```

Every service falls back to in-memory storage and local behavior when its upstream URLs are unset, so each one starts alone. See [Configuration](#configuration).

### Run the whole stack with Docker Compose

```bash
cp .env.example .env
```

Edit `.env` and set the values below (`openssl rand -hex 32` generates a good random value).

| Variable | Requirement |
|----------|-------------|
| `JWT_SIGNING_KEY` | Random string of at least 32 characters, shared by the services that validate tokens |
| `DEV_CLIENT_SECRET` | Required by `docker-compose.yml` for interpolation (any non-empty string). It has no effect today: the stack has no seeded client, because auth-server delegates client authentication to client-registry-service |
| `POSTGRES_PASSWORD` | Password for the Postgres container |
| `REDIS_PASSWORD` | Password for the Redis container |
| `LOGIN_UI_SERVICE_TOKEN` | At least 32 characters; shared between `login-ui` and `auth-server`'s `POST /internal/issue-code` (ADR-0011) |
| `INTROSPECTION_SECRET` | Pre-shared bearer secret for `token-introspection-service` (RFC 7662 §2.1); it will not start without one |

```bash
docker compose up --build
```

All seven services start in parallel, with Postgres and Redis behind them. Each exposes `/health`.

| Service | Host URL |
|---------|----------|
| auth-server | http://localhost:9080 |
| identity-service | http://localhost:9081 |
| client-registry-service | http://localhost:9082 |
| token-introspection-service | http://localhost:9083 |
| authorization-policy-service | http://localhost:9084 |
| example-resource-service | http://localhost:9085 |
| login-ui | http://localhost:9087 |

Useful Compose commands:

```bash
docker compose up --build -d       # detached
docker compose logs -f auth-server # follow one service
docker compose ps                  # status and health
docker compose down                # stop and remove containers
```

---

## Usage

Issue a token, inspect it, revoke it. This runs against a single service and needs no Docker.

```bash
# 1. Start auth-server with a seeded development client (client id "dev-client").
AUTH_DEV_SEED_CLIENTS=true AUTH_DEV_CLIENT_SECRET=dev-secret task run:auth-server &

# 2. Request a token (client_credentials grant).
TOKEN=$(curl -s -X POST http://localhost:8080/oauth/token \
  -d grant_type=client_credentials -d client_id=dev-client \
  -d client_secret=dev-secret -d scope=read | jq -r .access_token)

# 3. Introspect it. Introspection and revocation require client authentication.
curl -s -X POST http://localhost:8080/oauth/introspect \
  -u dev-client:dev-secret -d token=$TOKEN
```

```json
{"active":true,"client_id":"dev-client","sub":"dev-client","iss":"identity-platform","scope":"read","exp":1794962924,"iat":1794962624,"token_type":"Bearer","jti":"28a6f44896a3f62d8d37c1d64c6bac07"}
```

```bash
# 4. Revoke it, then introspect again.
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8080/oauth/revoke \
  -u dev-client:dev-secret -d token=$TOKEN        # 200
curl -s -X POST http://localhost:8080/oauth/introspect \
  -u dev-client:dev-secret -d token=$TOKEN         # {"active":false}
```

The Compose stack has no seeded client (auth-server delegates client authentication to `client-registry-service`, which starts empty). Register one first, then use the host ports from the table above:

```bash
CLIENT=$(curl -s -X POST http://localhost:9082/clients -H 'Content-Type: application/json' \
  -d '{"name":"demo","scopes":["read","write"],"grant_types":["client_credentials"]}')

curl -s -X POST http://localhost:9080/oauth/token \
  -d grant_type=client_credentials -d scope=read \
  -d client_id=$(echo "$CLIENT" | jq -r .client_id) \
  -d client_secret=$(echo "$CLIENT" | jq -r .client_secret)
```

Keep the returned `client_secret`: the registry does not show it again.

> The Compose-specific steps were not executed when this README was last revised, because the Docker host was out of disk space. The single-service steps above were executed.

---

## Examples

Each example builds on the `dev-client` setup from [Usage](#usage). Outputs are from real runs.

### 1. A token is verifiable without calling the server

Why: resource servers should validate tokens locally, not on every request.

```bash
curl -s http://localhost:8080/.well-known/jwks.json | jq -r '.keys[].kid'
# dev-edde52bbeb2e0525

echo $TOKEN | jq -R 'split(".")[0] | @base64d | fromjson' -c
# {"alg":"RS256","kid":"dev-edde52bbeb2e0525","typ":"at+jwt"}
```

The `kid` in the token header names the key in the JWKS. Without `AUTH_JWT_RSA_PRIVATE_KEY_PEM`, auth-server generates a new key at every start, so the `kid` changes on restart; set the PEM to keep it stable.

### 2. Introspection never returns an error for a bad token

Why: RFC 7662 says an unknown or expired token is a normal answer, not a failure. Callers must not have to tell "bad token" from "bad request".

```bash
curl -s -w " %{http_code}\n" -X POST http://localhost:8080/oauth/introspect \
  -u dev-client:dev-secret -d token=garbage
# {"active":false} 200
```

Gotcha: this is `200`, not `401`. A `401` here means your *client* credentials were wrong. Revocation is idempotent in the same way: revoking an already revoked token also returns `200`.

### 3. Scopes are capped by registration

Why: a client must never receive more than it registered for.

```bash
curl -s -X POST http://localhost:8080/oauth/token -d grant_type=client_credentials \
  -d client_id=dev-client -d client_secret=dev-secret -d scope="read write" | jq -r .scope
# read write

curl -s -X POST http://localhost:8080/oauth/token -d grant_type=client_credentials \
  -d client_id=dev-client -d client_secret=dev-secret -d scope=admin
# {"error":"invalid_scope","error_description":"requested scope not permitted"}
```

| Request `scope` | Result |
|-----------------|--------|
| `read` | granted |
| `read write` | granted (both registered for `dev-client`) |
| `admin` | `invalid_scope`, no token |

### 4. A password reset that never reveals who has an account

Why: a reset form that answers differently for known and unknown addresses lets anyone enumerate your users. The default `stdout` email sender prints the link to the service log, so no mail server is needed here.

```bash
IDENTITY_SERVER_PORT=8081 IDENTITY_LOG_FORMAT=json task run:identity-service &

curl -s -X POST http://localhost:8081/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","name":"Ada","password":"old password 123"}' > /dev/null

# Known and unknown addresses get the same answer: 204.
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8081/auth/request-password-reset \
  -H 'Content-Type: application/json' -d '{"email":"ada@example.com"}'    # 204
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8081/auth/request-password-reset \
  -H 'Content-Type: application/json' -d '{"email":"nobody@example.com"}' # 204
```

The service log for the known address contains a `reset_url` field (with no `IDENTITY_EMAIL_PASSWORD_RESET_URL_TEMPLATE` set, it is the bare token). Redeem it, then sign in:

```bash
curl -s -X POST http://localhost:8081/auth/reset-password -H 'Content-Type: application/json' \
  -d '{"token":"<token from the log>","new_password":"new password 456"}'
# {"user_id":"...","email":"ada@example.com"}

for pw in "old password 123" "new password 456"; do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8081/auth/login \
    -H 'Content-Type: application/json' -d "{\"email\":\"ada@example.com\",\"password\":\"$pw\"}"
done
# 401   (old password rejected)
# 200   (new password accepted)
```

Gotcha: a reset token works once. Running the redeem command a second time fails with `401`, and a password shorter than 8 characters is rejected with `400` without using up the token.

To send real email, see [Configuring email](#configuring-email).

---

## Architecture

All services follow the **Ports and Adapters** (Hexagonal) architecture with a strict dependency direction:

```text
domain  -->  application  -->  ports  -->  adapters
```

| Layer         | Responsibility                                                        |
|---------------|-----------------------------------------------------------------------|
| **Domain**    | Pure business models and repository interfaces. No framework imports. |
| **Application** | Business logic. Depends only on domain interfaces.                 |
| **Ports**     | Inbound and outbound port interfaces.                                 |
| **Adapters**  | Infrastructure implementations (HTTP handlers, in-memory repos, JWT). |

This design ensures that business logic is framework-agnostic, independently testable, and that infrastructure can be swapped without modifying core logic.

### Service Map

```text
Relying party ──> auth-server (:8080) ──302 /sign-in?login_challenge=<id>──> login-ui (:8087)
                       ^                                                         │
                       │  POST /internal/issue-code (bearer token)               │ verify credentials
                       └─────────────────────────────────────────────────────────┤
                                                                                 v
                                                                        identity-service (:8081)

auth-server ──> client-registry-service (:8082)   client authentication
auth-server ──> authorization-policy-service (:8084)   roles and permissions for token claims
example-resource-service (:8085) ──> token-introspection-service (:8083)
                                 ──> authorization-policy-service (:8084)
login-ui, auth-server, identity-service ──> entitlements-service (:8086)   accounts and plans
```

All inter-service communication is over **HTTP**. There is no shared database between services. Ports are the defaults for a directly run service; Docker Compose maps `8080`–`8087` to host ports `9080`–`9087`.

### Services

#### [auth-server](services/auth-server/README.md) (`:8080`)

The OAuth 2.0 / OIDC authorization server. Issues, introspects and revokes tokens; publishes JWKS and discovery metadata.

- Grants: `client_credentials`, `refresh_token`, `authorization_code` (mandatory PKCE-S256), device authorization, token exchange, JWT-bearer and SAML-bearer.
- Uses the **Strategy pattern** through a `GrantStrategyRegistry`; adding a grant does not touch the dispatcher.
- RS256 signing with a `previous`/`current`/`next` key window.

#### [identity-service](services/identity-service/README.md) (`:8081`)

User records and credentials: registration, login, email verification and password reset, with bcrypt hashing. It does not issue tokens. Stores users in memory, SQLite or PostgreSQL depending on configuration, sends mail through a pluggable sender (`stdout`, `noop`, `smtp`), and rate limits the password-reset endpoints.

#### [client-registry-service](services/client-registry-service/README.md) (`:8082`)

OAuth client registrations: CRUD, credential validation, and dynamic client registration (RFC 7591/7592).

#### [token-introspection-service](services/token-introspection-service/README.md) (`:8083`)

Standalone token validation and metadata extraction per [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662).

#### [authorization-policy-service](services/authorization-policy-service/README.md) (`:8084`)

Fine-grained authorization using the **Strategy** and **Specification** patterns: evaluates RBAC policies for a subject and resource.

#### [example-resource-service](services/example-resource-service/README.md) (`:8085`)

A protected API that shows bearer-token validation and scope enforcement (`read`, `write`), with two layers: scope (local) and policy (an outbound call).

#### [entitlements-service](services/entitlements-service/README.md) (`:8086`)

Account, seat and plan state: "does this actor have this entitlement, now?" (ADR-0027, ADR-0028). Not part of the Docker Compose stack.

#### [login-ui](services/login-ui/) (`:8087`)

The user-facing screens (ADR-0011): sign-in, sign-up, password reset, device approval, billing and account switching. `auth-server`'s `/oauth/authorize` redirects the browser to `login-ui /sign-in?login_challenge=<id>`; login-ui verifies credentials with `identity-service`, redeems the challenge at `auth-server`, and sends the browser back to the relying party.

### Shared Libraries

Shared code lives in external modules, required directly by each service's `go.mod`:

| Package | Module | Purpose |
|---------|--------|---------|
| `apperrors` | `github.com/jedi-knights/go-platform/apperrors` | Typed errors with HTTP status mapping |
| `httputil`, `httpmw`, `httpserver` | `github.com/jedi-knights/go-platform/...` | Response helpers, the shared middleware stack, server lifecycle and health handlers |
| `jwtutil` | `github.com/jedi-knights/go-platform/jwtutil` | The `Claims` type, `Sign`, `Parse*`, shared by `auth-server` and `token-introspection-service` |
| `container` | `github.com/jedi-knights/go-platform/container` | Dependency-injection container used by every service's composition root |
| `testutil` | `github.com/jedi-knights/go-platform/testutil` | Test helpers |
| `logging` | `github.com/jedi-knights/go-logging/pkg/logging` | `slog`-based structured logging |

### Design Patterns

| Pattern                    | Where Used                                          |
|----------------------------|-----------------------------------------------------|
| **Strategy**               | Grant type handling, token generation, password hashing |
| **Repository**             | Data access abstraction in domain interfaces        |
| **Adapter**                | HTTP handlers, outbound adapters                    |
| **Chain of Responsibility**| HTTP middleware pipeline                            |
| **Specification**          | Policy evaluation rules                             |
| **Registry / Factory**     | Grant strategy registry                             |

---

## API Reference

Every service also exposes `GET /health`. Interactive docs for the services that generate them are at `/swagger/index.html` (see [Swagger](#swagger--api-documentation)).

### auth-server

| Method | Path | Description |
|--------|------|-------------|
| POST | `/oauth/token` | Issue a token (RFC 6749) |
| GET | `/oauth/authorize` | Authorization endpoint; redirects to login-ui |
| POST | `/oauth/par` | Pushed authorization requests (RFC 9126) |
| POST | `/oauth/introspect` | Token introspection (RFC 7662); requires client authentication |
| POST | `/oauth/revoke` | Token revocation (RFC 7009); requires client authentication |
| POST | `/device_authorization` | Device authorization (RFC 8628) |
| GET, POST | `/userinfo` | OIDC UserInfo |
| GET | `/.well-known/jwks.json` | Public RSA keys (RS256 mode only) |
| GET | `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| POST | `/internal/issue-code` | login-ui redeems a login challenge (bearer token) |
| POST | `/internal/device/decision` | login-ui approves or denies a device code (bearer token) |

### identity-service

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Register a user |
| POST | `/auth/login` | Verify credentials |
| POST | `/auth/request-verification` | Send an email-verification link |
| POST | `/auth/verify-email` | Redeem a verification token |
| POST | `/auth/request-password-reset` | Send a reset link (always `204`) |
| POST | `/auth/reset-password` | Redeem a reset token and set a password |
| GET | `/users/{id}/claims` | User claims for token issuance |
| GET, PUT | `/users/{id}/active-account` | Read or set the user's active account |

### client-registry-service

| Method | Path | Description |
|--------|------|-------------|
| POST | `/clients` | Register a client |
| GET | `/clients` | List clients |
| GET | `/clients/{id}` | Get a client |
| DELETE | `/clients/{id}` | Delete a client |
| POST | `/clients/validate` | Validate client credentials |
| POST, GET, PUT, DELETE | `/register`, `/register/{client_id}` | Dynamic client registration (RFC 7591/7592) |

### token-introspection-service

| Method | Path | Description |
|--------|------|-------------|
| POST | `/introspect` | Introspect a token |

### authorization-policy-service

| Method | Path | Description |
|--------|------|-------------|
| POST | `/evaluate` | Evaluate an authorization request |
| GET | `/subjects/{subjectID}/permissions` | Roles and permissions for a subject |

### example-resource-service

| Method | Path | Description |
|--------|------|-------------|
| GET | `/resources` | List resources (requires `read`) |
| GET | `/resources/{id}` | Get a resource (requires `read`) |
| POST | `/resources` | Create a resource (requires `write`) |
| GET | `/resources/sensitive`, `/resources/dpop-protected` | Step-up and DPoP demonstrations |

### entitlements-service

| Method | Path | Description |
|--------|------|-------------|
| POST | `/accounts/personal` | Create a personal account (idempotent) |
| POST | `/accounts/{account_id}/invites` | Invite a user |
| POST | `/accounts/{account_id}/plans` | Activate a plan |
| POST | `/accounts/{account_id}/transfer-ownership` | Transfer ownership |
| DELETE | `/accounts/{account_id}/seats/{user_id}` | Remove a seat |
| GET | `/users/{user_id}/seats` | List a user's seats |

### login-ui

Browser pages, not a JSON API: `/sign-in`, `/sign-up`, `/forgot-password`, `/reset-password`, `/device`, `/accounts`, and `/billing/{plans,checkout,portal,return}`.

---

## Configuration

### auth-server

| Variable                                  | Default              | Description                                                                                                  |
|-------------------------------------------|----------------------|--------------------------------------------------------------------------------------------------------------|
| `AUTH_SERVER_HOST`                        | `0.0.0.0`            | Server bind host                                                                                             |
| `AUTH_SERVER_PORT`                        | `8080`               | Server port                                                                                                  |
| `AUTH_JWT_SIGNING_ALG`                    | `RS256`              | `RS256` (default) or `HS256` (legacy fallback)                                                               |
| `AUTH_JWT_RSA_PRIVATE_KEY_PEM`            | _unset_              | PEM-encoded current RSA private key (RS256 mode). Unset → in-memory keypair generated at startup            |
| `AUTH_JWT_RSA_PRIVATE_KEY_PEM_NEXT`       | _unset_              | Optional pre-staged successor key; published in JWKS ahead of promotion                                      |
| `AUTH_JWT_RSA_PRIVATE_KEY_PEM_PREVIOUS`   | _unset_              | Optional retiring key; stays in JWKS for the rotation drain window                                           |
| `AUTH_JWT_SIGNING_KEY`                    | _unset_              | HMAC signing key (HS256 mode only)                                                                           |
| `AUTH_JWT_ISSUER`                         | `identity-platform`  | JWT issuer claim                                                                                             |
| `AUTH_TOKEN_TTL_SECONDS`                  | `3600`               | Token time-to-live                                                                                           |
| `AUTH_LOG_LEVEL`                          | `info`               | Log level                                                                                                    |
| `AUTH_DEV_SEED_CLIENTS`                   | `false`              | Seed a development client with id `dev-client`. Local development only                                       |
| `AUTH_DEV_CLIENT_SECRET`                  | _unset_              | Secret for `dev-client` when seeding is on                                                                    |

The JWKS document is available at `GET /.well-known/jwks.json` whenever `AUTH_JWT_SIGNING_ALG=RS256`. Under HS256 the route is not registered.

ADR-0009 adds the authorization_code grant. Its only new env var is:

| Variable                                  | Default | Description                                                                    |
|-------------------------------------------|---------|--------------------------------------------------------------------------------|
| `AUTH_AUTHORIZATION_CODE_TTL_SECONDS`     | `60`    | Authorization code lifetime. Tighter values shrink the exfiltration window.   |

Authorization codes are persisted in Redis (atomic GET+DEL via Lua) when `AUTH_REDIS_URL` is set, otherwise the in-memory adapter is used. PKCE-S256 is mandatory for every client; `plain` is rejected.

### identity-service

| Variable                   | Default       | Description      |
|----------------------------|---------------|------------------|
| `IDENTITY_SERVER_HOST`     | `0.0.0.0`    | Server bind host |
| `IDENTITY_SERVER_PORT`     | `8081`        | Server port      |
| `IDENTITY_EMAIL_SENDER`    | `stdout`      | `stdout` (logs the link), `noop`, or `smtp`. See [Configuring email](#configuring-email) |
| `IDENTITY_EMAIL_FROM`      | _(empty)_     | Sender address, e.g. `Identity <noreply@example.com>`. Required for `smtp` |
| `IDENTITY_EMAIL_SMTP_HOST` | _(empty)_     | SMTP relay host. Required for `smtp` |
| `IDENTITY_EMAIL_SMTP_PORT` | `587`         | Relay submission port (STARTTLS). Port 465 is not supported |
| `IDENTITY_EMAIL_SMTP_USERNAME` | _(empty)_ | Relay login; set together with the password |
| `IDENTITY_EMAIL_SMTP_PASSWORD` | _(empty)_ | Relay password. A secret: never put it in `fly.*.toml` |
| `IDENTITY_EMAIL_PASSWORD_RESET_URL_TEMPLATE` | _(empty)_ | Link emailed for password reset; `{{token}}` is replaced. Empty sends the bare token |
| `IDENTITY_EMAIL_PASSWORD_RESET_TOKEN_TTL_SECS` | `3600` | How long a reset link works |
| `IDENTITY_RATELIMIT_TRUSTED_PROXIES` | _(empty)_ | CIDRs whose `X-Forwarded-For` is trusted for per-user reset rate limiting |

#### Configuring email

Out of the box identity-service only **logs** password-reset links (`stdout`), so reset works
for developers but real users never receive anything. To deliver mail you need an SMTP relay
(SES, Postmark, Mailgun, your own) and a sending domain verified with it (SPF/DKIM), then:

1. **Set the non-secret settings.** Locally, export them; on Fly, add them to `[env]` in
   [`fly.identity-service.toml`](fly.identity-service.toml):

   ```bash
   IDENTITY_EMAIL_SENDER=smtp
   IDENTITY_EMAIL_SMTP_HOST=smtp.example.com
   IDENTITY_EMAIL_SMTP_PORT=587
   IDENTITY_EMAIL_FROM="Identity <noreply@example.com>"
   ```

2. **Set the secrets.** On Fly, use secrets so they stay out of git:

   ```bash
   fly secrets set -a jk-identity-service \
     IDENTITY_EMAIL_SMTP_USERNAME=... IDENTITY_EMAIL_SMTP_PASSWORD=...
   ```

3. **Point reset links at login-ui.** `IDENTITY_EMAIL_PASSWORD_RESET_URL_TEMPLATE` must be the
   public URL of login-ui's `/reset-password` page with a `{{token}}` placeholder (already set
   to `https://jk-login-ui.fly.dev/reset-password?token={{token}}` in `fly.identity-service.toml`).
   login-ui also needs `LOGIN_UI_IDENTITY_SERVICE_URL` set, or `/forgot-password` and
   `/reset-password` return 503.

4. **Verify.** Redeploy, open `/forgot-password` on login-ui, and submit a registered address.
   The email should arrive within a minute. The page shows the same confirmation whether or not
   the send worked (that is deliberate, to avoid revealing which addresses have accounts), so if
   nothing arrives, check identity-service's logs for `request password reset failed`: a failed send names the SMTP stage (`connecting`, `STARTTLS`, `authentication`,
   `RCPT TO rejected`, ...) but never the password or the link.

Things to know:

- **Startup fails on incomplete settings.** `smtp` without a host or `IDENTITY_EMAIL_FROM`, or a
  username without a password, stops the service rather than silently dropping mail. Set the
  secrets *before* switching `IDENTITY_EMAIL_SENDER`, or the deploy will crash-loop.
- **Credentials go over TLS only.** The relay must offer STARTTLS on the configured port;
  otherwise login is refused (localhost relays are exempt, for development).
- **The same sender serves email verification.** `IDENTITY_EMAIL_VERIFICATION_URL_TEMPLATE`
  controls that link.
- **Per-user reset rate limits behind login-ui.** To limit by end user instead of by login-ui's
  address, set `IDENTITY_RATELIMIT_TRUSTED_PROXIES` on identity-service (Fly: `fdaa::/16`) and
  `LOGIN_UI_SERVER_CLIENT_IP_HEADER` on login-ui (Fly: `Fly-Client-IP`). Both are set in the
  checked-in Fly configs. Leave them empty where login-ui is not behind a proxy that overwrites
  the header.

### client-registry-service

| Variable                   | Default       | Description      |
|----------------------------|---------------|------------------|
| `CLIENT_SERVER_HOST`       | `0.0.0.0`    | Server bind host |
| `CLIENT_SERVER_PORT`       | `8082`        | Server port      |

### token-introspection-service

| Variable                          | Default | Description                                                                                  |
|-----------------------------------|---------|----------------------------------------------------------------------------------------------|
| `INTROSPECT_SERVER_PORT`          | `8083`  | Server port                                                                                  |
| `INTROSPECT_JWT_JWKS_URL`         | _unset_ | When set, validate tokens as RS256 via JWKS. Takes precedence over HS256 signing key         |
| `INTROSPECT_JWT_JWKS_CACHE_TTL`   | `1h`    | How long a successful JWKS fetch is cached (Go duration string)                              |
| `INTROSPECT_JWT_SIGNING_KEY`      | _unset_ | HS256 HMAC signing key. Required only when `INTROSPECT_JWT_JWKS_URL` is unset                |

### authorization-policy-service

| Variable              | Default | Description |
|-----------------------|---------|-------------|
| `POLICY_SERVER_PORT`  | `8084`  | Server port |

### example-resource-service

| Variable                        | Default | Description                                                                                                                  |
|---------------------------------|---------|------------------------------------------------------------------------------------------------------------------------------|
| `RESOURCE_SERVER_PORT`          | `8085`  | Server port                                                                                                                  |
| `RESOURCE_INTROSPECTION_URL`    | _unset_ | When set, validate via token-introspection-service (handles revocation). Takes precedence over JWKS and HS256                |
| `RESOURCE_JWT_JWKS_URL`         | _unset_ | When set, validate tokens locally as RS256 via JWKS. Used when introspection is unset                                        |
| `RESOURCE_JWT_JWKS_CACHE_TTL`   | `1h`    | How long a successful JWKS fetch is cached                                                                                   |
| `RESOURCE_JWT_SIGNING_KEY`      | _unset_ | HS256 HMAC signing key. Required only when both `RESOURCE_INTROSPECTION_URL` and `RESOURCE_JWT_JWKS_URL` are unset            |

### login-ui

| Variable | Default | Description |
|---|---|---|
| `LOGIN_UI_SERVER_HOST` / `LOGIN_UI_SERVER_PORT` | `0.0.0.0` / `8087` | Bind address |
| `LOGIN_UI_AUTH_SERVER_URL` | _unset_ | auth-server base URL (needed to complete sign-in) |
| `LOGIN_UI_AUTH_SERVER_SERVICE_TOKEN` | _unset_ | Bearer token for `POST /internal/issue-code`; must match `AUTH_LOGIN_UI_SERVICE_TOKEN`. A secret |
| `LOGIN_UI_IDENTITY_SERVICE_URL` | _unset_ | identity-service base URL. Without it, sign-up and password reset return `503` |
| `LOGIN_UI_ENTITLEMENTS_SERVICE_URL` | _unset_ | entitlements-service base URL |
| `LOGIN_UI_SERVER_CLIENT_IP_HEADER` | _unset_ | Header an edge proxy sets to the real client IP (Fly: `Fly-Client-IP`); forwarded for per-user rate limiting |

### entitlements-service

Variables use the `ENTITLEMENTS_` prefix; see the [service README](services/entitlements-service/README.md).

---

## Deployment (Fly.io)
All six services deploy to [Fly.io](https://fly.io) as **private** apps in region `iad`
(no public IPs) behind the public [`jk-api-gateway`](https://github.com/jedi-knights/api-gateway),
which is the only ingress. They reach each other and the gateway reaches them over Fly's
private `.internal` network. Each service builds from the shared root `Dockerfile`, selected by
the `SERVICE_NAME` build arg in its own `fly.<service>.toml`.

### Topology

| Service (Fly app) | Port | Postgres | Redis |
|---|---|---|---|
| `jk-auth-server` | 8080 | – | token store |
| `jk-identity-service` | 8081 | ✅ | – |
| `jk-client-registry-service` | 8082 | ✅ | – |
| `jk-token-introspection-service` | 8083 | – | revocation |
| `jk-authorization-policy-service` | 8084 | ✅ | cache |

Backing services: one **Fly Managed Postgres** cluster (a database per Postgres-backed service)
and one **Upstash Redis** instance, both in `iad`.

> `example-resource-service` is a reference/demo consumer (not core identity infrastructure),
> so it is intentionally **not deployed** — its source remains in the repo as an integration
> example. Add it back to `deploy.yml` and create `fly.example-resource-service.toml` if you
> want it running.

> **Private networking note:** each service sets `<PREFIX>_SERVER_HOST=[::]` in its `fly.*.toml`.
> Fly's `.internal` network is IPv6; a service bound to the default `0.0.0.0` (IPv4-only) is
> unreachable over it. The value must be `[::]` (not `::`) because the services build the
> listen address by string concatenation (`host:port`), so `[::]` yields the valid `[::]:8080`
> dual-stack listener while `::` would produce the unparseable `:::8080`.

### Provision the backing services (one-time)

```bash
fly mpg create --name jk-identity-pg --region iad        # Managed Postgres cluster

# Attach a database + connection secret to each Postgres-backed app:
fly mpg attach <cluster-id> --app jk-identity-service             --variable-name IDENTITY_DATABASE_URL
fly mpg attach <cluster-id> --app jk-client-registry-service      --variable-name CLIENT_DATABASE_URL
fly mpg attach <cluster-id> --app jk-authorization-policy-service --variable-name POLICY_DATABASE_URL

fly redis create --name jk-identity-redis --region iad   # Upstash Redis; note the redis:// URL
```

Schema migrations are embedded (`//go:embed`) and run automatically at each service's startup —
no separate migration step.

### Secrets

Fly secrets are per app. Generate the shared values once
(`openssl rand -hex 32`) and set them so they match across services:

```bash
fly secrets set AUTH_JWT_SIGNING_KEY="$JWT_KEY" AUTH_DEV_CLIENT_SECRET="$DEV" \
  AUTH_REDIS_URL="$REDIS_URL" -a jk-auth-server
fly secrets set INTROSPECT_JWT_SIGNING_KEY="$JWT_KEY" \
  INTROSPECT_INTROSPECTION_SECRET="$INTRO_SECRET" INTROSPECT_REDIS_URL="$REDIS_URL" \
  -a jk-token-introspection-service
fly secrets set POLICY_REDIS_URL="$REDIS_URL" -a jk-authorization-policy-service
```

The **JWT signing key must be identical** on `auth-server` and `token-introspection` (tokens
issued by auth-server are validated by introspection). If you later deploy
`example-resource-service`, it must share the same `JWT_SIGNING_KEY` and an
`INTROSPECTION_SECRET` matching `token-introspection`.

### Deploy

```bash
fly apps create jk-<service>                  # once per service (reserves the name, no public IP)
fly deploy -c fly.<service>.toml              # build + release; deploy dependencies first
```

Pushes to `main` then redeploy all services automatically via
[`.github/workflows/deploy.yml`](.github/workflows/deploy.yml), authenticated with the
`jedi-knights` org `FLY_API_TOKEN` secret.

### Verify (no public IPs — tunnel privately)

```bash
fly proxy 8081 -a jk-identity-service &
curl -fsS localhost:8081/health               # expect 200
```

End-to-end, request a token for a client registered with the registry, through the gateway at
`https://jk-api-gateway.fly.dev/oauth/token` and call `/resources` with it.

---

## Horizontal Scalability
**Production deployment of this platform has no application-controllable single points of failure.** Every service runs at N ≥ 2 machines per region behind Fly's proxy, every stateful backing service is deployed in HA mode with automatic failover, and every service refuses to start in production without its durable state URL set. This is the reference implementation's teaching claim: *how* to build a horizontally scalable identity platform, not just what one looks like at N=1.

The full contract lives in [ADR-0029](docs/adr/0029-reliable-horizontal-scalability-no-spofs.md). This section is the operational summary.

### Requirements — non-negotiable in production

| Requirement | Why | How |
|---|---|---|
| No SPOF at the Redis layer | Redis holds tokens, refresh tokens, authorization codes, login challenges, PAR requests, device codes, and every replay-protection `jti` cache. A single-node Redis outage blocks issuance, revocation, and introspection. | Redis Sentinel (≥3 sentinels, ≥1 replica), Redis Cluster (≥3 primaries, ≥1 replica per primary), or a managed HA equivalent (Upstash Global with automatic failover, Fly Redis with replicas, AWS ElastiCache Multi-AZ) |
| No SPOF at the Postgres layer | Postgres holds users, credentials, clients, roles, policies, resources. Single-primary loss blocks every write path. | Streaming replication with automatic failover, or a managed HA equivalent (Fly Managed Postgres HA cluster, RDS Multi-AZ, Cloud SQL HA, Neon with automatic failover) |
| N ≥ 2 machines per service | Rolling deploy, single-machine failure, and Fly machine restarts must not cause an outage. | `min_machines_running = 2` in every `fly.<service>.toml`, or `fly scale count 2 -a <app>` |
| Fail-fast on missing durable state | The memory fallback is silent — the service can't know its own replica count and can't detect the incorrect deployment on its own. | Startup guard: when `*_LOG_ENVIRONMENT=production` and the required state URL is empty, the service exits with a non-zero status |
| Readiness gates on backing-store reachability | Fly's proxy must drain machines whose Redis or Postgres connectivity has degraded. | `/ready` (or platform-equivalent readiness probe) checks backing-store reachability. `/health` remains liveness-only |
| Retries with backoff on failover windows | Postgres primary failover and Redis Sentinel failover produce a bounded window of write failures (seconds). | Exponential backoff with jitter on outbound calls; ≤3 attempts for reads, ≤1 for non-idempotent writes; circuit breaker on outbound HTTP to sibling services |

Multi-region deployment is **architecturally compatible** with this design (services are stateless, adapters are env-driven, Fly's `primary_region` + `[[regions]]` block supports it operationally) but is not required by ADR-0029 — a well-configured single-region deployment satisfies the "no application-controllable SPOFs" bar. Two known follow-up dependencies must be closed before an actual multi-region deployment: (1) cross-region JWKS distribution — signing keys are currently per-process env vars, so rotation windows leave one region ahead of another; (2) cross-region refresh-token reuse-detection consistency — [ADR-0014](docs/adr/0014-refresh-token-rotation-replay.md)'s rotate-on-use is race-free only under a strongly-consistent Redis topology. See [ADR-0029 §6](docs/adr/0029-reliable-horizontal-scalability-no-spofs.md) for detail.

### State-path inventory

Every state path resolves to a shared HA store in production. In development, memory adapters remain the default per ADR-0004 — the fallback exists so contributors can run one service with `go run ./cmd/serve.go` and zero external dependencies.

| Service | Ephemeral state (Redis, HA) | Relational state (Postgres, HA) | Production env vars |
|---|---|---|---|
| `auth-server` | access tokens, refresh tokens, authorization codes, login challenges, PAR requests, device authorizations, client-assertion `jti` replay, DPoP proof `jti` replay | — (delegates client lookup to `client-registry-service`) | `AUTH_REDIS_URL` |
| `token-introspection-service` | revocation lookup | — | `INTROSPECT_REDIS_URL` |
| `authorization-policy-service` | policy-decision cache (60s TTL, fails open on Redis errors) | roles, policies | `POLICY_REDIS_URL` + `POLICY_DATABASE_URL` |
| `client-registry-service` | — | clients + secrets | `CLIENT_DATABASE_URL` |
| `identity-service` | — | users + credentials | `IDENTITY_DATABASE_URL` |

Adapter implementations for every path already ship — see `services/<name>/internal/adapters/outbound/{memory,redis,postgres}/`. The container wiring in each service's `internal/container/container.go` selects the durable adapter when the env var above is set. Under ADR-0029 the production fallback path is *not* memory; it is exit-with-error.

### Development vs production behavior

| Behavior | Development (`*_LOG_ENVIRONMENT` unset or `development`) | Production (`*_LOG_ENVIRONMENT=production`) |
|---|---|---|
| State URL unset | Log a warning, fall back to in-memory adapter, continue | Log the missing variable, exit with non-zero status |
| Backing store unreachable at startup | Retry with backoff, continue serving with degraded functionality | `/ready` fails; Fly drains the machine; retries with backoff continue until reachable |
| Machine count | 1 (default) | ≥2 per service, per region |

The fatal-in-production guard is the design commitment from ADR-0029 §3. It is not "operator discipline"; it is a startup check that a production service refuses to run without its durable state configured.

### Scaling procedure

1. **Provision HA backing services** — one-time per environment. HA Fly Managed Postgres cluster (`fly mpg create --ha` or equivalent), HA Redis (Upstash Global, Fly Redis with replicas, or a managed HA offering). Single-node Redis and single-primary Postgres are development-only configurations.
2. **Attach durable state URLs as Fly secrets** — see the [Secrets](#secrets) subsection. Every `*_URL` in the state-path inventory must be set for every service intended to scale.
3. **Confirm secrets are set:**
   ```bash
   fly secrets list -a jk-auth-server                    | grep -E 'AUTH_REDIS_URL'
   fly secrets list -a jk-token-introspection-service    | grep -E 'INTROSPECT_REDIS_URL'
   fly secrets list -a jk-authorization-policy-service   | grep -E 'POLICY_(REDIS|DATABASE)_URL'
   fly secrets list -a jk-client-registry-service        | grep -E 'CLIENT_DATABASE_URL'
   fly secrets list -a jk-identity-service               | grep -E 'IDENTITY_DATABASE_URL'
   ```
   Under the ADR-0029 startup guard, a missing secret in production means the service will refuse to start on next deploy. Fix before deploying, not after.
4. **Scale to N ≥ 2** per service:
   ```bash
   fly scale count 2 -a jk-auth-server
   fly scale count 2 -a jk-identity-service
   fly scale count 2 -a jk-client-registry-service
   fly scale count 2 -a jk-token-introspection-service
   fly scale count 2 -a jk-authorization-policy-service
   ```
5. **Verify HA end-to-end.** Drive traffic through the gateway: mint a token, introspect it, revoke it, re-introspect it. All four operations must observe consistent state regardless of which replica served each request. Then trigger a failover event (`fly machine restart` on one machine per service, then on a Redis or Postgres node if the managed offering exposes that operation) and confirm the same four-step check still passes with no visible errors.

### Services not yet in production

`login-ui`, `entitlements-service`, and `example-resource-service` are in the repo but not in `.github/workflows/deploy.yml`. Before adding any to the deploy matrix:

- **`login-ui`** — holds no per-request session state today. Handler comments mark the promissory notes where a signed session cookie will land (`services/login-ui/internal/adapters/inbound/http/handler.go`, search for `signed session cookie`). Under ADR-0029, when session state is introduced it must be either self-contained (signed + encrypted cookie, no server state) or backed by the HA Redis instance — no per-machine session store.
- **`entitlements-service`** — has a Postgres adapter; the startup guard requires `ENTITLEMENTS_DATABASE_URL` under `production`. Add it as a Fly secret before the first production deploy.
- **`example-resource-service`** — reference/demo consumer, intentionally excluded from the deploy matrix. If deployed, requires the same guard-gated `*_DATABASE_URL` treatment plus a JWT verification config.

---

## Development

```bash
task build       # build the six core services into bin/
task lint        # golangci-lint across all modules
task test        # unit + integration tests
```

### Testing

# Run all tests (unit + integration)
task test

# Unit tests only (with race detection and coverage)
task test:unit

# Integration tests only
task test:integration
```text

#### Local Acceptance Testing

`test/acceptance` is a separate Go module containing a full [godog](https://github.com/cucumber/godog)/Gherkin BDD suite that exercises the platform's entire *implemented* OAuth 2.0/OIDC surface end-to-end, plus a smaller `@smoke` suite that exercises the real `docker-compose.yml` stack. Both build real service binaries and start containers, so they're excluded from `task test`/`task test:unit`/`task test:integration` by design.

##### Prerequisites

- Docker running — the acceptance suite starts one shared Redis container per run; the smoke suite brings up the full `docker-compose.yml` stack.
- The Allure command line tool, only if you want to view results as an HTML report instead of plain console pass/fail — consult Allure's own documentation for the install steps on your platform (e.g. Homebrew on macOS).

##### Running the acceptance suite

```bash
# Single command: run the suite, generate the Allure report, open it in your browser
task test:acceptance:all
```text

Or run the pieces individually:

```bash
task test:acceptance          # pretty console output only (default)
task test:acceptance:allure   # same suite, additionally writes Allure JSON results
task test:acceptance:report   # runs test:acceptance:allure, then generates + opens the HTML report
```text

Run a single feature file during development. The suite has no domain tags to filter by — each scenario tags its own `@topology:*` internally rather than sharing one feature-level tag — so filter by path instead:

```bash
ACCEPTANCE_PATHS=features/token_revocation.feature task test:acceptance
```text

Other environment variables the suite reads (all optional):

| Variable | Default | Purpose |
|---|---|---|
| `ACCEPTANCE_FORMAT` | `pretty` | godog output format — set to `allure` to produce Allure JSON results (`test:acceptance:allure` sets this for you) |
| `ACCEPTANCE_CONCURRENCY` | `1` | Number of scenarios to run in parallel — every scenario builds a fully isolated `World`, so this is safe at any value |
| `ACCEPTANCE_PATHS` | `features` (the whole directory) | Comma-separated feature file(s) or directory to run |

##### What's covered

Each feature file's header comment names the RFC(s) and ADR(s) it exercises — the same comment becomes every scenario's description in the Allure report, so the report doubles as a compliance matrix.

| Feature file | RFC / ADR |
|---|---|
| `client_credentials.feature` | RFC 6749 §4.4 |
| `authorization_code_pkce.feature` | RFC 6749 §4.1, RFC 7636, [ADR-0009](docs/adr/0009-authorization-code-pkce.md) |
| `refresh_token_rotation.feature` | RFC 6749 §6, [ADR-0014](docs/adr/0014-refresh-token-rotation-replay.md) |
| `token_revocation.feature` | RFC 7009 |
| `token_introspection.feature` | RFC 7662 |
| `bearer_token_usage.feature` | RFC 6750 |
| `jwks_key_rotation.feature` | RFC 7517, RFC 7518, [ADR-0008](docs/adr/0008-rs256-jwks-token-signing.md) |
| `oidc_core.feature` | OpenID Connect Core 1.0, [ADR-0010](docs/adr/0010-oidc-core.md) |
| `as_metadata.feature` | RFC 8414, OpenID Connect Discovery 1.0, [ADR-0012](docs/adr/0012-authorization-server-metadata.md) |
| `dynamic_client_registration.feature` | RFC 7591, RFC 7592, [ADR-0013](docs/adr/0013-dynamic-client-registration.md) |
| `token_exchange.feature` | RFC 8693, [ADR-0016](docs/adr/0016-token-exchange-rfc-8693.md) |
| `rich_authorization_requests.feature` | RFC 9396, [ADR-0017](docs/adr/0017-rich-authorization-requests-rfc-9396.md) |
| `login_challenge_handoff.feature` | [ADR-0011](docs/adr/0011-login-ui-service.md) |

See [Architecture Decision Records](#architecture-decision-records) for the full ADR index.

##### Smoke tests against the real Docker images

The acceptance suite above builds each service as an in-process/subprocess binary — it never touches the actual `Dockerfile` or `docker-compose.yml` wiring. The `@smoke` suite in `test/acceptance/smoke/` covers exactly that gap by driving the real `docker-compose.yml` stack over its real container network.

```bash
task test:smoke
```text

This generates fresh secrets, brings the full stack up (building images), runs the smoke scenarios, and tears the stack down afterward regardless of pass or fail. It needs Docker running and no other setup.

##### Adding new scenarios

Every scenario must be fully independent — safe to run in any order, at any concurrency, forever. The rule that makes this possible: **never hardcode a fixture ID** (a client, user, or resource name). Always mint a fresh one per scenario — see `support/fixtures.go`. This is what makes the shared Redis container safe under `ACCEPTANCE_CONCURRENCY` > 1.

#### Other Task Commands

```bash
task lint        # Run golangci-lint
task format      # Format code with gofmt and goimports
task mocks       # Generate mocks (go generate)
task tidy        # Sync go.work and tidy all modules
task clean       # Remove build artifacts
```text

### Swagger / API Documentation

The six core services ship with interactive [Swagger UI](https://swagger.io/tools/swagger-ui/) documentation, powered by [swaggo/swag](https://github.com/swaggo/swag). Start a service and open its Swagger UI in your browser:

| Service                      | Swagger UI URL                                        |
|------------------------------|-------------------------------------------------------|
| auth-server                  | [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html) |
| identity-service             | [http://localhost:8081/swagger/index.html](http://localhost:8081/swagger/index.html) |
| client-registry-service      | [http://localhost:8082/swagger/index.html](http://localhost:8082/swagger/index.html) |
| token-introspection-service  | [http://localhost:8083/swagger/index.html](http://localhost:8083/swagger/index.html) |
| authorization-policy-service | [http://localhost:8084/swagger/index.html](http://localhost:8084/swagger/index.html) |
| example-resource-service     | [http://localhost:8085/swagger/index.html](http://localhost:8085/swagger/index.html) |

`login-ui` and `entitlements-service` do not serve Swagger UI.

#### Regenerating Swagger Docs

If you modify handler annotations or request/response types, regenerate the docs:

```bash
# All services at once
task swagger

# Or a single service
task swagger:auth-server
task swagger:identity-service
task swagger:client-registry-service
task swagger:token-introspection-service
task swagger:authorization-policy-service
task swagger:example-resource-service
```text

This requires the `swag` CLI tool:

```bash
go install github.com/swaggo/swag/cmd/swag@latest
```text

### Project Structure

```
identity-platform-go/
├── go.work                    # Go workspace: every module below
├── Taskfile.yml               # build, test, lint, swagger tasks
├── Dockerfile                 # one image, built per service with SERVICE_NAME
├── docker-compose.yml         # local stack (seven services, Postgres, Redis)
├── fly.<service>.toml         # Fly.io config per deployed service
├── docs/
│   ├── adr/                   # Architecture Decision Records
│   └── README.md              # architecture notes
├── test/acceptance/           # godog/Gherkin suite and docker-compose smoke tests
├── init/postgres/             # database bootstrap for Compose
├── infra/                     # Lago and Stripe configuration
└── services/
    ├── auth-server/
    ├── identity-service/
    ├── client-registry-service/
    ├── token-introspection-service/
    ├── authorization-policy-service/
    ├── example-resource-service/
    ├── entitlements-service/
    └── login-ui/
```text

Each service follows the same layout:

```
services/<name>/
├── cmd/main.go              # entry point
└── internal/
    ├── domain/              # models and repository interfaces; no framework imports
    ├── application/         # business logic
    ├── ports/               # inbound and outbound interfaces
    ├── adapters/            # inbound/http, outbound/<store or service>
    ├── config/              # viper-based configuration
    └── container/           # dependency wiring
```text

### Architecture Decision Records

Key design decisions are documented in [`docs/adr/`](docs/adr/):

| ADR | Decision |
|-----|----------|
| [ADR-0001](docs/adr/0001-use-ports-and-adapters.md) | Use Ports and Adapters Architecture |
| [ADR-0002](docs/adr/0002-use-go-workspaces.md) | Use Go Workspaces for Monorepo |
| [ADR-0003](docs/adr/0003-use-strategy-pattern-for-grants.md) | Use Strategy Pattern for OAuth2 Grant Type Handling |
| [ADR-0004](docs/adr/0004-in-memory-persistence-for-reference.md) | Use In-Memory Persistence for Reference Implementation |
| [ADR-0005](docs/adr/0005-adapter-scalability-contract.md) | Adapter Scalability Contract via Compile-Time Interface Checks |
| [ADR-0006](docs/adr/0006-redis-token-storage.md) | Use Redis for Token Storage and Revocation |
| [ADR-0007](docs/adr/0007-postgresql-relational-data.md) | Use PostgreSQL for Relational Service Data |
| [ADR-0008](docs/adr/0008-rs256-jwks-token-signing.md) | Use RS256 + JWKS for Access Token Signing |
| [ADR-0009](docs/adr/0009-authorization-code-pkce.md) | Authorization Code Grant with Mandatory PKCE |
| [ADR-0010](docs/adr/0010-oidc-core.md) | OpenID Connect Core 1.0 |
| [ADR-0011](docs/adr/0011-login-ui-service.md) | Unified Login & Registration Service (`login-ui`) |
| [ADR-0012](docs/adr/0012-authorization-server-metadata.md) | Authorization Server Metadata (RFC 8414 + OIDC Discovery) |
| [ADR-0013](docs/adr/0013-dynamic-client-registration.md) | Dynamic Client Registration (RFC 7591 + RFC 7592) |
| [ADR-0014](docs/adr/0014-refresh-token-rotation-replay.md) | Refresh Token Rotation, Family Tracking, and Replay Detection |
| [ADR-0015](docs/adr/0015-agent-principal-type.md) | Agent Principal Type — `actor_type` and `agent_id` Claims |
| [ADR-0016](docs/adr/0016-token-exchange-rfc-8693.md) | Token Exchange (RFC 8693) for Agent-to-Agent Delegation |
| [ADR-0017](docs/adr/0017-rich-authorization-requests-rfc-9396.md) | Rich Authorization Requests (RFC 9396) |
| [ADR-0018](docs/adr/0018-agent-audit-event-schema.md) | Agent Audit Event Schema |
| [ADR-0019](docs/adr/0019-usage-accounting-and-billing.md) | Usage Accounting via the Audit Pipeline (Lago + Stripe) |
| [ADR-0020](docs/adr/0020-authorization-server-issuer-identification.md) | Authorization Server Issuer Identification (RFC 9207) |
| [ADR-0021](docs/adr/0021-pushed-authorization-requests.md) | Pushed Authorization Requests (RFC 9126) |
| [ADR-0022](docs/adr/0022-device-authorization-flow.md) | Device Authorization Flow (RFC 8628) |
| [ADR-0023](docs/adr/0023-jwt-bearer-client-authentication.md) | JWT-Bearer Client Authentication (RFC 7521 / RFC 7523) |
| [ADR-0024](docs/adr/0024-step-up-authentication-challenge.md) | Step-Up Authentication Challenge (RFC 9470) |
| [ADR-0025](docs/adr/0025-dpop-proof-of-possession.md) | DPoP — Demonstrating Proof of Possession (RFC 9449) |
| [ADR-0026](docs/adr/0026-saml2-bearer-assertion-grant.md) | SAML 2.0 Bearer Assertion Grant (RFC 7522) |
| [ADR-0027](docs/adr/0027-entitlements-enforces-quota-lago-prices.md) | Entitlements-service enforces quotas; Lago only prices |
| [ADR-0028](docs/adr/0028-entitlements-model.md) | Entitlements model — account, check location, bundles, catalog, meter |
| [ADR-0029](docs/adr/0029-reliable-horizontal-scalability-no-spofs.md) | Reliable Horizontal Scalability without Single Points of Failure |

---

## Release Process

Each service is versioned and released independently by [go-semantic-release](https://github.com/jedi-knights/go-semantic-release), driven by [Conventional Commits](https://www.conventionalcommits.org/). The release tool only versions the modules declared in [`.semantic-release.yaml`](.semantic-release.yaml); a service not listed there is not tagged.

A release runs when a commit lands on `main` and touches `services/` or the config. For each module, the tool reads the commits since that module's last tag:

| Commit type | Effect |
|---|---|
| `feat:` | Minor bump (`v1.2.0` to `v1.3.0`) |
| `fix:`, `perf:`, `refactor:` | Patch bump (`v1.2.0` to `v1.2.1`) |
| `feat!:` or a `BREAKING CHANGE:` footer | Major bump (`v1.2.0` to `v2.0.0`) |
| `chore:`, `docs:`, `style:`, `ci:`, `test:` | No release |

Tags are `<service>/v<version>`, for example `auth-server/v0.9.0`. **Never merge to `main` with a failing check**: the merge can publish a broken release.

### Configuration

```yaml
release_mode: independent        # each module is versioned on its own
projects:
  - name: auth-server
    path: services/auth-server   # commits touching this path count toward auth-server
    tag_prefix: "auth-server/"   # must end with "/"
```text

### Repository settings

The workflow uses the automatic `GITHUB_TOKEN`. Under **Settings, Actions, General**, set **Workflow permissions** to *Read and write permissions* and enable *Allow GitHub Actions to create and approve pull requests*; without write permission the tagging step fails.

### Running releases locally

```bash
task deps                                              # installs the release tool
semantic-release --dry-run --no-ci                     # preview, no mutations
semantic-release detect-projects --no-ci               # which modules are discovered
semantic-release --project auth-server --dry-run --no-ci
```text

`--no-ci` is required outside CI; otherwise the tool refuses to run unless `GH_TOKEN` is set.

---

## Contributing

There is no `CONTRIBUTING.md`; this is the process.

1. Open an issue describing the change, or pick an existing one.
2. Branch from `main`. Name the branch after the commit it will produce, for example `fix/reset-redeem-limit-client-ip`.
3. Write the failing test first, then the code. Services are tested through their public surface with hand-written fakes (no mock generator).
4. Run `task lint` and `task test` before pushing. CI runs lint per module, unit, integration and acceptance tests.
5. Commit with [Conventional Commits](https://www.conventionalcommits.org/): `<type>(<scope>): <description>`, lowercase, imperative, no trailing period. One pull request carries one `type(scope)`.
6. Open a pull request against `main`. **Do not merge until every check is green**: merging to `main` triggers a release and a production deploy of all services.

Architecture rules that review will enforce: `domain` imports nothing outside the standard library; `application` depends only on domain interfaces; HTTP handlers depend on ports, not on application types; wiring happens only in `internal/container`. Read [`CLAUDE.md`](CLAUDE.md) and the relevant ADR before changing token, client or grant behavior.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE). This project is a reference implementation for educational and demonstration purposes.
