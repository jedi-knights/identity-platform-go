# Architecture Documentation

## Overview

This repository implements a production-quality OAuth2/OIDC microservices reference platform in Go, following Ports and Adapters (Hexagonal Architecture) with strict dependency direction.

## Service Map

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Identity Platform                                  │
│                                                                           │
│  Client App ──▶ auth-server (:8080) ──▶ identity-service (:8081)        │
│                      │                                                    │
│                      ▼                                                    │
│              client-registry-service (:8082)                              │
│                                                                           │
│  token-introspection-service (:8083)                                      │
│  authorization-policy-service (:8084)                                     │
│                                                                           │
│  example-resource-service (:8085)  ← protected API                       │
└─────────────────────────────────────────────────────────────────────────┘
```

## Services

| Service | Port | Responsibility |
|---------|------|----------------|
| auth-server | 8080 | OAuth2 token issuance, introspection, revocation |
| identity-service | 8081 | User management, authentication |
| client-registry-service | 8082 | OAuth2 client registration and validation |
| token-introspection-service | 8083 | JWT token validation and metadata |
| authorization-policy-service | 8084 | RBAC policy evaluation |
| example-resource-service | 8085 | Protected API demonstrating JWT auth |

## Dependency Direction

```
domain → application → ports → adapters
```

- **domain**: Pure business models and repository interfaces. No external dependencies.
- **application**: Business logic. Depends only on domain interfaces.
- **ports**: Input/output port interfaces.
- **adapters**: Infrastructure implementations (HTTP, in-memory repos, JWT).

## Design Patterns

| Pattern | Where Used |
|---------|-----------|
| Strategy | Grant type handling, token generation, password hashing |
| Repository | Data access abstraction in domain interfaces |
| Adapter | HTTP handlers, outbound adapters |
| Chain of Responsibility | HTTP middleware pipeline |
| Specification | Policy evaluation rules |
| Registry/Factory | Grant strategy registry |

## Shared Libraries

| Library | Purpose |
|---------|---------|
| libs/logging | Structured slog-based logging with trace ID support |
| libs/errors | Typed application errors with HTTP status mapping |
| libs/httputil | HTTP response helpers and middleware |
| libs/testutil | Testing utilities |

## Communication

All inter-service communication is over HTTP only. There is no shared database between services.
