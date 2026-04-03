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

> **Important:** Change `jwt.signing_key` before deploying to production.

## Quick Start

```bash
cd services/auth-server
go run ./cmd/...
```

### Request a token (client_credentials)

```bash
curl -s -X POST http://localhost:8080/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=test-client" \
  -d "client_secret=test-secret" \
  -d "scope=read"
```

### Introspect a token

```bash
curl -s -X POST http://localhost:8080/oauth/introspect \
  -d "token=<access_token>"
```

### Revoke a token

```bash
curl -s -X POST http://localhost:8080/oauth/revoke \
  -d "token=<access_token>"
```

## Build

```bash
go build ./...
```
