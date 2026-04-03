# ADR-0002: Use Go Workspaces for Monorepo

## Status
Accepted

## Context
We want a monorepo where multiple Go modules (services and shared libraries) can be developed together without publishing each module to a registry during development.

## Decision
Use `go work` (Go workspaces, Go 1.18+) to manage the monorepo. Each service and library is an independent Go module with its own `go.mod`. The root `go.work` file declares all modules.

## Consequences
- Local development works seamlessly across all modules.
- Each service can be versioned and released independently.
- No need for local `replace` directives in production builds.
- `go.work` is not used in production Docker builds — each service is built independently.
