# ADR-0006: Use Redis for Token Storage and Revocation

**Status**: Accepted  
**Date**: 2026-04-05

## Context

`auth-server` issues JWT access tokens and stores them via `domain.TokenRepository` — three operations: `Save`, `FindByRaw`, and `Delete`. `Delete` is the revocation path; `FindByRaw` lets the system confirm that a token is still present (i.e., has not been revoked) independently of whether its JWT signature is valid.

`token-introspection-service` currently validates tokens by verifying the JWT signature alone. It has no visibility into the revocation store. This means a token that has been explicitly revoked via `POST /revoke` is still reported as active by introspection until it expires naturally — a correctness gap that becomes more severe as token lifetimes increase.

The deeper problem is the in-memory `TokenRepository` in each `auth-server` replica. Each process holds its own independent copy of the token store, so a revocation applied to replica A is invisible to replica B, and to `token-introspection-service` running as any separate process. This violates the correctness guarantee that revocation is supposed to provide.

The system needs a shared, external token store that:

1. Both `auth-server` instances (all replicas) write to — as the sole writer
2. `token-introspection-service` reads from — to confirm a token has not been revoked
3. Automatically expires entries — to avoid unbounded growth without a background cleanup job

## Decision

Replace `auth-server`'s `memory.TokenRepository` with a Redis-backed adapter using `github.com/redis/go-redis/v9`.

### Key schema

```
token:<raw-jwt>  →  JSON-encoded token value
```

TTL is set to `token.ExpiresAt - now` at `Save` time, so Redis automatically cleans up expired tokens. No background expiry job is needed.

### Adapter operations

| Operation | Redis command | Behaviour |
|-----------|--------------|-----------|
| `Save(token)` | `SETEX token:<raw> <ttl-seconds> <json>` | Stores the token; TTL matches JWT expiry |
| `FindByRaw(raw)` | `GET token:<raw>` | `redis.Nil` → not found (revoked or never issued) |
| `Delete(raw)` | `DEL token:<raw>` | Revokes the token immediately |

### Revocation check in token-introspection-service

`token-introspection-service` gains a new `RevocationChecker` port:

```go
type RevocationChecker interface {
    IsRevoked(ctx context.Context, rawToken string) (bool, error)
}
```

The Redis adapter for this port issues `EXISTS token:<raw>`. A token is considered active only when both conditions hold:

1. The JWT signature is valid and the claims are not expired
2. `EXISTS token:<raw>` returns 1 (key is present — not revoked)

`auth-server` is the sole writer of this keyspace. `token-introspection-service` is read-only.

### Environment variables and fallback

| Service | Env var | Fallback |
|---------|---------|---------|
| `auth-server` | `AUTH_REDIS_URL` | in-memory `TokenRepository` |
| `token-introspection-service` | `INTROSPECT_REDIS_URL` | JWT-signature-only validation (current behaviour) |

When the env var is absent, each service falls back to its existing behaviour. This preserves the ability to run individual services in isolation during local development without a Redis instance. The fallback is wired in `container.go` following the same pattern used for other outbound adapters (see `AUTH_CLIENT_REGISTRY_URL`, `AUTH_IDENTITY_SERVICE_URL`).

### Compile-time interface check

Both the `auth-server` Redis adapter and the `token-introspection-service` `RevocationChecker` adapter must include the standard blank-identifier check (see ADR-0005):

```go
var _ domain.TokenRepository = (*TokenRepository)(nil)
var _ ports.RevocationChecker = (*RevocationChecker)(nil)
```

## Consequences

**Positive**

- Revocation is honoured within milliseconds across all replicas of `auth-server` and `token-introspection-service`.
- Redis TTL enforces token expiry in the store automatically — no background cleanup job.
- Token metadata is inspectable during debugging via `redis-cli` (`KEYS token:*`, `TTL token:<raw>`).
- The `RevocationChecker` port keeps `token-introspection-service` decoupled from Redis: the adapter can be swapped (e.g., to a database-backed blacklist) without touching introspection logic.

**Negative / Trade-offs**

- Redis becomes a single point of failure for token operations. Mitigated by Redis Sentinel (high availability) or Redis Cluster (horizontal scale) at the infrastructure layer.
- A Redis outage blocks token issuance, revocation, and introspection. The fallback to in-memory is only for local development — it is not a production resilience strategy.
- Raw JWT strings used as keys can be large (typically 200–400 bytes for HS256 tokens). Key size is manageable at typical token volumes but should be monitored.
- Cross-service operational dependency: `auth-server` and `token-introspection-service` must be pointed at the same Redis instance. This is a deployment-time concern, not a code concern.

## Alternatives Considered

- **Shared PostgreSQL token table**: Provides durability and queryability but introduces higher latency per token operation and requires a schema migration. Redis TTL is a better fit for an ephemeral, time-bounded keyspace.
- **Token blacklist only (store revoked tokens, not active ones)**: Reduces write volume but requires the store to outlive the token's natural expiry to remain authoritative. It also inverts the lookup semantics (`EXISTS` for revocation vs. `NOT EXISTS` for active). The current approach — store active tokens, delete on revoke — is simpler and consistent with the existing `TokenRepository` interface contract.
- **JWKS + short-lived tokens (no revocation store)**: Valid for some threat models but does not support immediate revocation. Incompatible with the existing `POST /revoke` endpoint and RFC 7009 semantics.
