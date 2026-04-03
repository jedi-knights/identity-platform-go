# Identity Platform Go

A production-style **OAuth 2.0 / OIDC** reference platform built in Go, demonstrating a pure microservices architecture with clean design principles. Each service is independently deployable with its own module, configuration, and in-memory data store.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Service Map](#service-map)
- [Services](#services)
- [Shared Libraries](#shared-libraries)
- [Design Patterns](#design-patterns)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Architecture Decision Records](#architecture-decision-records)
- [License](#license)

---

## Overview

This repository is a **reference implementation** that showcases how to build a scalable identity and access management platform using:

- **Hexagonal Architecture** (Ports & Adapters) with strict dependency direction
- **Go Workspaces** for monorepo management across independent modules
- **Strategy Pattern** for extensible OAuth 2.0 grant type handling
- **Specification Pattern** for fine-grained authorization policy evaluation
- **Zero external dependencies** for local development (all persistence is in-memory)

The platform implements core OAuth 2.0 flows including token issuance, introspection, and revocation, along with user identity management, client registration, and resource protection via JWT-based authentication.

---

## Architecture

All services follow the **Ports and Adapters** (Hexagonal) architecture with a strict dependency direction:

```
domain  -->  application  -->  ports  -->  adapters
```

| Layer         | Responsibility                                                        |
|---------------|-----------------------------------------------------------------------|
| **Domain**    | Pure business models and repository interfaces. No framework imports. |
| **Application** | Business logic. Depends only on domain interfaces.                 |
| **Ports**     | Inbound and outbound port interfaces.                                 |
| **Adapters**  | Infrastructure implementations (HTTP handlers, in-memory repos, JWT). |

This design ensures that business logic is framework-agnostic, independently testable, and that infrastructure can be swapped without modifying core logic.

---

## Service Map

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          Identity Platform                               │
│                                                                          │
│   Client App ──> auth-server (:8080) ──> identity-service (:8081)       │
│                       │                                                  │
│                       v                                                  │
│               client-registry-service (:8082)                            │
│                                                                          │
│   token-introspection-service (:8083)                                    │
│   authorization-policy-service (:8084)                                   │
│                                                                          │
│   example-resource-service (:8085)  <-- protected API                   │
└──────────────────────────────────────────────────────────────────────────┘
```

All inter-service communication is over **HTTP**. There is no shared database between services.

---

## Services

### auth-server (`:8080`)

The core OAuth 2.0 authorization server. Issues access tokens, performs token introspection, and handles token revocation.

- Implements `client_credentials` grant type (fully functional)
- `authorization_code` and `refresh_token` grants are stubbed for extension
- Uses the **Strategy Pattern** via a `GrantStrategyRegistry` to route grant requests
- JWT token generation with configurable signing key, issuer, and TTL

### identity-service (`:8081`)

Handles user registration and authentication. Provides bcrypt-based password hashing with an in-memory user store.

### client-registry-service (`:8082`)

Manages OAuth 2.0 client registrations. Provides full CRUD operations and client credential validation.

### token-introspection-service (`:8083`)

Standalone JWT token validation and metadata extraction per [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662).

### authorization-policy-service (`:8084`)

Fine-grained authorization using the **Strategy** and **Specification** patterns. Evaluates RBAC policies against subjects and resources.

### example-resource-service (`:8085`)

A protected API that demonstrates JWT-based authentication and scope enforcement. Requires valid tokens with appropriate scopes (`read`, `write`) to access resources.

---

## Shared Libraries

Located in `libs/`, these are independent Go modules shared across services:

| Library          | Purpose                                            |
|------------------|----------------------------------------------------|
| `libs/logging`   | Structured `slog`-based logging with trace ID support |
| `libs/errors`    | Typed application errors with HTTP status mapping  |
| `libs/httputil`  | HTTP response helpers and middleware               |
| `libs/testutil`  | Testing utilities                                  |

---

## Design Patterns

| Pattern                    | Where Used                                          |
|----------------------------|-----------------------------------------------------|
| **Strategy**               | Grant type handling, token generation, password hashing |
| **Repository**             | Data access abstraction in domain interfaces        |
| **Adapter**                | HTTP handlers, outbound adapters                    |
| **Chain of Responsibility**| HTTP middleware pipeline                            |
| **Specification**          | Policy evaluation rules                             |
| **Registry / Factory**     | Grant strategy registry                             |

---

## Getting Started

### Prerequisites

- **Go 1.24+**
- **[Task](https://taskfile.dev/)** (task runner) - optional but recommended

### Run a Service

Each service can be run independently:

```bash
# Using Task
task run:auth-server
task run:identity-service
task run:client-registry-service

# Or directly with Go
cd services/auth-server && go run ./cmd/...
```

### Quick Test: Issue a Token

```bash
# Start the auth server
task run:auth-server

# Request a token using client_credentials grant
curl -s -X POST http://localhost:8080/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=test-client" \
  -d "client_secret=test-secret" \
  -d "scope=read"
```

### Build All Services

```bash
task build
# Binaries are output to bin/
```

---

## Configuration

Each service is configured via environment variables with a service-specific prefix, or through a `config.yaml` file loaded by [Viper](https://github.com/spf13/viper).

### auth-server

| Variable                  | Default                   | Description              |
|---------------------------|---------------------------|--------------------------|
| `AUTH_SERVER_HOST`        | `0.0.0.0`                | Server bind host         |
| `AUTH_SERVER_PORT`        | `8080`                   | Server port              |
| `AUTH_JWT_SIGNING_KEY`    | `change-me-in-production`| JWT HMAC signing key     |
| `AUTH_JWT_ISSUER`         | `identity-platform`      | JWT issuer claim         |
| `AUTH_TOKEN_TTL_SECONDS`  | `3600`                   | Token time-to-live       |
| `AUTH_LOG_LEVEL`          | `info`                   | Log level                |

### identity-service

| Variable                   | Default       | Description      |
|----------------------------|---------------|------------------|
| `IDENTITY_SERVER_HOST`     | `0.0.0.0`    | Server bind host |
| `IDENTITY_SERVER_PORT`     | `8081`        | Server port      |

### client-registry-service

| Variable                   | Default       | Description      |
|----------------------------|---------------|------------------|
| `CLIENT_SERVER_HOST`       | `0.0.0.0`    | Server bind host |
| `CLIENT_SERVER_PORT`       | `8082`        | Server port      |

### token-introspection-service

| Variable                      | Default | Description          |
|-------------------------------|---------|----------------------|
| `INTROSPECT_SERVER_PORT`      | `8083`  | Server port          |
| `INTROSPECT_JWT_SIGNING_KEY`  | -       | JWT HMAC signing key |

### authorization-policy-service

| Variable              | Default | Description |
|-----------------------|---------|-------------|
| `POLICY_SERVER_PORT`  | `8084`  | Server port |

### example-resource-service

| Variable                    | Default | Description          |
|-----------------------------|---------|----------------------|
| `RESOURCE_SERVER_PORT`      | `8085`  | Server port          |
| `RESOURCE_JWT_SIGNING_KEY`  | -       | JWT HMAC signing key |

---

## API Reference

### auth-server

| Method | Path                | Description                    |
|--------|---------------------|--------------------------------|
| POST   | `/oauth/token`      | Issue access token (RFC 6749)  |
| GET    | `/oauth/authorize`  | Authorization endpoint (stub)  |
| POST   | `/oauth/introspect` | Token introspection (RFC 7662) |
| POST   | `/oauth/revoke`     | Token revocation (RFC 7009)    |
| GET    | `/health`           | Health check                   |

### identity-service

| Method | Path              | Description         |
|--------|-------------------|---------------------|
| POST   | `/auth/register`  | Register a new user |
| POST   | `/auth/login`     | Authenticate a user |
| GET    | `/health`         | Health check        |

### client-registry-service

| Method | Path                  | Description                 |
|--------|-----------------------|-----------------------------|
| POST   | `/clients`            | Register a new OAuth client |
| GET    | `/clients`            | List all registered clients |
| GET    | `/clients/{id}`       | Get a specific client       |
| DELETE | `/clients/{id}`       | Delete a client             |
| POST   | `/clients/validate`   | Validate client credentials |
| GET    | `/health`             | Health check                |

### token-introspection-service

| Method | Path          | Description      |
|--------|---------------|------------------|
| POST   | `/introspect` | Introspect token |
| GET    | `/health`     | Health check     |

### authorization-policy-service

| Method | Path        | Description              |
|--------|-------------|--------------------------|
| POST   | `/evaluate` | Evaluate authorization   |
| GET    | `/health`   | Health check             |

### example-resource-service

| Method | Path              | Description                          |
|--------|-------------------|--------------------------------------|
| GET    | `/resources`      | List resources (requires `read`)     |
| GET    | `/resources/{id}` | Get resource by ID (requires `read`) |
| POST   | `/resources`      | Create resource (requires `write`)   |
| GET    | `/health`         | Health check (no auth)               |

---

## Testing

```bash
# Run all tests (unit + integration)
task test

# Unit tests only (with race detection and coverage)
task test:unit

# Integration tests only
task test:integration
```

### Other Task Commands

```bash
task lint        # Run golangci-lint
task format      # Format code with gofmt and goimports
task mocks       # Generate mocks (go generate)
task tidy        # Sync go.work and tidy all modules
task clean       # Remove build artifacts
```

---

## Project Structure

```
identity-platform-go/
├── go.work                          # Go workspace definition
├── Taskfile.yml                     # Task runner configuration
├── docs/
│   ├── README.md                    # Architecture documentation
│   └── adr/                         # Architecture Decision Records
│       ├── 0001-use-ports-and-adapters.md
│       ├── 0002-use-go-workspaces.md
│       ├── 0003-use-strategy-pattern-for-grants.md
│       └── 0004-in-memory-persistence-for-reference.md
├── libs/
│   ├── errors/                      # Typed application errors
│   ├── httputil/                    # HTTP helpers and middleware
│   ├── logging/                     # Structured slog-based logging
│   └── testutil/                    # Test utilities
└── services/
    ├── auth-server/                 # OAuth2 authorization server
    │   ├── cmd/main.go
    │   └── internal/
    │       ├── adapters/            # HTTP handlers, in-memory repos
    │       ├── application/         # Grant strategies, token service
    │       ├── config/              # Viper-based configuration
    │       ├── container/           # Dependency injection
    │       ├── domain/              # Token, client, grant models
    │       ├── observability/       # Logging setup
    │       └── ports/               # Inbound & outbound interfaces
    ├── identity-service/            # User registration & auth
    ├── client-registry-service/     # OAuth client management
    ├── token-introspection-service/ # JWT validation (RFC 7662)
    ├── authorization-policy-service/# RBAC policy evaluation
    └── example-resource-service/    # Protected resource API
```

---

## Architecture Decision Records

Key design decisions are documented in `docs/adr/`:

| ADR | Decision |
|-----|----------|
| [ADR-0001](docs/adr/0001-use-ports-and-adapters.md) | Use Ports and Adapters (Hexagonal) architecture for all services |
| [ADR-0002](docs/adr/0002-use-go-workspaces.md) | Use Go Workspaces for monorepo management |
| [ADR-0003](docs/adr/0003-use-strategy-pattern-for-grants.md) | Use Strategy Pattern for OAuth2 grant type handling |
| [ADR-0004](docs/adr/0004-in-memory-persistence-for-reference.md) | Use in-memory persistence for the reference implementation |

---

## License

This project is a reference implementation for educational and demonstration purposes.
