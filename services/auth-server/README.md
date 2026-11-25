# auth-server

OAuth2 Authorization Server microservice for the identity-platform-go monorepo.

## Overview

Implements OAuth 2.0 token endpoints using a hexagonal (ports & adapters) architecture:

- **Domain layer** – token, client, and grant models + repository interfaces
- **Application layer** – grant strategy registry (Strategy pattern), JWT/opaque token generation, token introspection/revocation
- **Ports** – inbound (`TokenIssuer`, `TokenIntrospector`, `TokenRevoker`) and outbound (domain repository interfaces)
- **Adapters** – inbound HTTP handlers; outbound in-memory repositories

## Endpoints

| Method | Path                | Description                        |
|--------|---------------------|------------------------------------|
| POST   | `/oauth/token`      | Issue access token (RFC 6749)      |
| GET    | `/oauth/authorize`  | Authorization endpoint (stub)      |
| POST   | `/oauth/introspect` | Token introspection (RFC 7662)     |
| POST   | `/oauth/revoke`     | Token revocation (RFC 7009)        |
| GET    | `/health`           | Health check                       |

## Supported Grant Types

| Grant Type           | Status           |
|----------------------|------------------|
| `client_credentials` | ✅ Implemented   |
| `authorization_code` | 🚧 Stub only     |
| `refresh_token`      | 🚧 Not yet       |

## Configuration

Configuration is loaded via [Viper](https://github.com/spf13/viper) from a `config.yaml` file or environment variables (prefix: `AUTH`).

| Key                   | Env var                   | Default                    |
|-----------------------|---------------------------|----------------------------|
| `server.host`         | `AUTH_SERVER_HOST`        | `0.0.0.0`                  |
| `server.port`         | `AUTH_SERVER_PORT`        | `8080`                     |
| `jwt.signing_key`     | `AUTH_JWT_SIGNING_KEY`    | `change-me-in-production`  |
| `jwt.issuer`          | `AUTH_JWT_ISSUER`         | `identity-platform`        |
| `token.ttl_seconds`   | `AUTH_TOKEN_TTL_SECONDS`  | `3600`                     |
| `log.level`           | `AUTH_LOG_LEVEL`          | `info`                     |
| `log.format`          | `AUTH_LOG_FORMAT`         | `json`                     |
| `log.environment`     | `AUTH_LOG_ENVIRONMENT`    | `development`              |
| `jwt.plan_scope_claim_namespace` | `AUTH_JWT_PLAN_SCOPE_CLAIM_NAMESPACE` | *empty* (opt-in) |

> **Important:** Change `jwt.signing_key` before deploying to production.

### Opt-in: plan_scope claim projection

Set `AUTH_JWT_PLAN_SCOPE_CLAIM_NAMESPACE` to a URI the deploy owns (e.g. `https://thecutline.app/plan_scope`) to project prefixed scope strings into a private JSON claim under that key on every issued token. Recognised prefixes: `tier:`, `sport:`, `div:`, `group:`, `feature:`, `history-depth:`. Empty namespace is a no-op pass-through — every existing deploy stays wire-identical.

Example: a client registered with scopes `tier:pro sport:soccer-women div:d1 group:standings` produces a token whose payload includes:

```json
{
  "https://thecutline.app/plan_scope": {
    "tier": "pro",
    "sports": ["soccer-women"],
    "divisions": ["d1"],
    "endpoint_groups": ["standings"]
  }
}
```

The projection is deliberately narrow and cutline-shaped. A second resource server that wants the same pattern should add its own projection layer rather than generalise this one.

## Quick Start

```bash
cd services/auth-server
AUTH_DEV_SEED_CLIENTS=true AUTH_DEV_CLIENT_SECRET=dev-secret go run ./cmd/...
```

`AUTH_DEV_SEED_CLIENTS` seeds one in-memory client, `dev-client`. It only applies when `AUTH_CLIENT_REGISTRY_URL` is unset; otherwise clients come from client-registry-service.

### Request a token (client_credentials)

```bash
curl -s -X POST http://localhost:8080/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=dev-client" \
  -d "client_secret=dev-secret" \
  -d "scope=read"
```

### Introspect a token

```bash
curl -s -X POST http://localhost:8080/oauth/introspect \
  -u dev-client:dev-secret -d "token=<access_token>"
```

### Revoke a token

```bash
curl -s -X POST http://localhost:8080/oauth/revoke \
  -u dev-client:dev-secret -d "token=<access_token>"
```

## Build

```bash
go build ./...
```
