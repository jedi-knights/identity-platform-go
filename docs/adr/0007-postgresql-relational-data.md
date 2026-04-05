# ADR-0007: Use PostgreSQL for Relational Service Data

**Status**: Accepted  
**Date**: 2026-04-05

## Context

Four services own relational data and currently back it with in-memory repositories:

| Service | Data owned |
|---------|-----------|
| `identity-service` | Users, credentials |
| `client-registry-service` | OAuth2 clients and secrets |
| `authorization-policy-service` | Roles, policies |
| `example-resource-service` | Protected resources |

As documented in ADR-0004 and ADR-0005, the in-memory adapters are a deliberate choice for the reference implementation phase. Each replica holds its own independent copy of state. For read-only workloads this is acceptable, but for write operations it is functionally incorrect: a user registered on replica A cannot log in via replica B, and an OAuth2 client registered on one instance is invisible to all others.

The platform is now past the reference stage for these services. They need a shared, durable state store that:

1. Survives service restarts
2. Is consistent across all replicas of a service
3. Is schema-versioned so the schema evolves alongside the code

## Decision

Each service that owns relational data gets a PostgreSQL adapter. The driver and supporting libraries are:

| Library | Role |
|---------|------|
| `github.com/jackc/pgx/v5` | PostgreSQL driver |
| `github.com/jackc/pgx/v5/pgxpool` | Connection pooling |
| `github.com/golang-migrate/migrate/v4` | Schema migrations |
| `github.com/golang-migrate/migrate/v4/database/pgx/v5` | Migration driver (pgx/v5 — no lib/pq dependency) |

### Database isolation

Each service owns its own PostgreSQL **database** (not schema). There are no cross-service foreign keys and no shared tables. This enforces the same service-boundary rule that applies to the HTTP layer: services may not directly query each other's data stores.

| Service | Database name |
|---------|--------------|
| `identity-service` | `identity_service` |
| `client-registry-service` | `client_registry` |
| `authorization-policy-service` | `authorization_policy` |
| `example-resource-service` | `example_resource` |

### Connection string

Standard `postgres://` URL format:

```
postgres://user:password@host:port/dbname?sslmode=disable
```

Pool size tuning is done via the `pool_max_conns` query parameter rather than code — this keeps the configuration surface at the deployment layer. Default pool minimum is 4 connections.

### Migrations

Migrations use `github.com/golang-migrate/migrate/v4` with `//go:embed` so migration SQL files are compiled into the service binary. No separate migration runner is needed at deploy time.

```go
//go:embed migrations/*.sql
var migrations embed.FS
```

Migrations run at container startup, before the HTTP server begins accepting requests. `migrate.ErrNoChange` is explicitly ignored — it is not an error condition. Any other migration error causes the service to exit before serving traffic, preventing a partially migrated schema from being used.

### Environment variable and fallback

Each service reads `DATABASE_URL`. When the variable is absent, the service falls back to its in-memory adapter. This preserves the ability to run services in isolation during local development without a PostgreSQL instance, consistent with the fallback pattern established for other outbound adapters.

### Compile-time interface checks

PostgreSQL adapters follow the same convention as memory adapters (see ADR-0005). Each adapter file must include the blank-identifier check for its domain interface:

```go
var _ domain.UserRepository = (*UserRepository)(nil)
```

## Consequences

**Positive**

- All replicas of a service share consistent state. Writes on one instance are immediately visible to all others.
- Data survives service restarts and redeployments.
- Schema migrations are versioned, embedded in the binary, and run atomically at startup — no manual migration step in the deployment process.
- The `pgxpool` connection pool is safe for concurrent use and handles connection lifecycle automatically.
- `lib/pq` is not introduced as a dependency; the `pgx/v5` migrate driver keeps the dependency graph clean.

**Negative / Trade-offs**

- PostgreSQL becomes a single point of failure for each service. Mitigated by PostgreSQL high-availability configurations (streaming replication, pgBouncer, managed services such as RDS or Cloud SQL) at the infrastructure layer.
- Write throughput is bounded by a single primary until read replicas are added. This is acceptable for the current scale and can be addressed independently of this ADR.
- Local development now requires either a running PostgreSQL instance or the `DATABASE_URL` env var to be absent (falling back to in-memory). A `docker-compose.yml` at the repo root provides the standard local database setup.
- Schema migration failures at startup cause the service to exit. This is intentional — serving traffic against a mismatched schema is a worse failure mode than a clean startup abort.

## Alternatives Considered

- **SQLite**: Suitable for a single-instance reference implementation but does not support concurrent writers from multiple replicas. Not appropriate for a horizontally scaled service.
- **Single shared database with per-service schemas**: Reduces operational overhead (one database to manage) but couples services at the infrastructure layer, making independent deployments and migrations harder. The per-database model keeps service boundaries clean.
- **ORM (e.g., GORM, ent)**: Adds abstraction over raw SQL but obscures query behaviour, makes migration control less explicit, and introduces a large dependency. The `pgx/v5` + `golang-migrate` pairing provides full control with minimal surface area.
