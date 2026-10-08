# ADR-0029: Reliable Horizontal Scalability without Single Points of Failure

**Status**: Accepted
**Date**: 2026-09-25
**Supersedes (in part)**: [ADR-0004](0004-in-memory-persistence-for-reference.md), [ADR-0005](0005-adapter-scalability-contract.md), [ADR-0006](0006-redis-token-storage.md), [ADR-0007](0007-postgresql-relational-data.md)

## Context

Prior ADRs treat backing-service high availability as an infrastructure-layer concern that "can be mitigated" outside of application code:

- ADR-0004 accepts in-memory persistence as the default, on the premise that this is a reference implementation.
- ADR-0005 states that "the compile-time check does not itself address the scalability gap — it only makes the swap point explicit."
- ADR-0006 says "Redis becomes a single point of failure for token operations. Mitigated by Redis Sentinel (high availability) or Redis Cluster (horizontal scale) at the infrastructure layer."
- ADR-0007 says "PostgreSQL becomes a single point of failure for each service. Mitigated by PostgreSQL high-availability configurations… at the infrastructure layer."

That framing is now insufficient. This platform is a reference implementation *of a horizontally scalable identity provider* — the reference value lies in demonstrating how such a system is built, not merely in showing that its core protocol flows are correct. A reference implementation that ships with SPOFs at every state layer teaches the wrong lesson.

This ADR promotes "no single points of failure" from a mitigation option to a mandatory production requirement, and specifies what that means concretely at the application, deployment, and backing-service layers.

## Decision

Production deployment of this platform must have **no application-controllable single points of failure**. The following requirements are non-negotiable:

### 1. Backing services deploy in HA mode

| Backing service | HA requirement | Acceptable configurations |
|---|---|---|
| Redis (ephemeral state — tokens, refresh tokens, auth codes, login challenges, PAR requests, device codes, `jti` replay caches) | Automatic failover, no data loss on primary failure within the durability window Redis provides | Redis Sentinel (≥3 sentinels, ≥1 replica); Redis Cluster (≥3 primary shards, ≥1 replica per shard); a managed HA offering that provides equivalent guarantees (Upstash Global with automatic failover, AWS ElastiCache with Multi-AZ, GCP Memorystore with HA, Fly Redis with replicas) |
| PostgreSQL (relational state — users, credentials, clients, roles, policies, resources, entitlements) | Streaming replication with automatic failover; write-path failover time bounded and monitored | Patroni-managed cluster (≥1 primary + ≥1 replica); a managed HA offering (Fly Managed Postgres HA cluster, AWS RDS Multi-AZ, GCP Cloud SQL HA, Neon read-replicas plus automatic failover) |

A single-node Redis or single-primary Postgres without a hot standby **is not a production configuration** under this ADR, regardless of the operational maturity of the surrounding infrastructure. Backups do not substitute for HA — they address durability, not availability.

### 2. Every service runs at N ≥ 2 machines per region

`fly scale count 1` is a development configuration. Every service in the deploy matrix runs with `min_machines_running = 2` (or equivalent on other platforms) so that a single machine failure never causes an outage. Health-check-driven rolling deploys become non-blocking.

### 3. Startup guard: fail-fast on missing durable state

Each service checks its `*_LOG_ENVIRONMENT` variable at startup. When it is `"production"` and a required durable-state URL is unset, the service exits with a non-zero status and a log line naming the missing variable. The service does **not** fall back to the in-memory adapter in production.

Required per service:

| Service | Guarded env var |
|---|---|
| `auth-server` | `AUTH_REDIS_URL` |
| `token-introspection-service` | `INTROSPECT_REDIS_URL` |
| `authorization-policy-service` | `POLICY_REDIS_URL`, `POLICY_DATABASE_URL` |
| `client-registry-service` | `CLIENT_DATABASE_URL` |
| `identity-service` | `IDENTITY_DATABASE_URL` |
| `entitlements-service` (once deployed) | `ENTITLEMENTS_DATABASE_URL` |

Development (`*_LOG_ENVIRONMENT=development` or unset) preserves the in-memory fallback per ADR-0004 — this ADR does not change the local-dev story.

### 4. Readiness gates on backing-store reachability, distinct from liveness

Every service exposes two endpoints with distinct semantics:

| Endpoint | Semantics | What it gates | Fly config |
|---|---|---|---|
| `GET /health` | Liveness. The process is alive and responsive. Does **not** probe backing stores. | Fly's `[checks]` — machine restart on failure. | Continues to point at `/health`. |
| `GET /ready` | Readiness. The service can currently serve requests correctly, including reaching every required backing store. | Fly's `[[http_service.checks]]` — traffic-routing gate; a failing `/ready` drains the machine from the pool without restarting it. | New; must be added to each `fly.<service>.toml`. |

Implementation shape: a background goroutine per required backing store pings that store every 2–5 seconds (`context.WithTimeout(2*time.Second)`, `PING` for Redis, `SELECT 1` for Postgres) and updates a `sync.RWMutex`-guarded `ready bool`. `GET /ready` returns 200 only when every guarded flag is `true`, and 503 otherwise. Live-probing per request is rejected — Fly polls `/ready` frequently, and per-call latency is not warranted when the failure mode being detected has a much slower time constant than the poll interval.

Splitting `/health` from `/ready` is deliberate. A Redis outage does not mean the process is dead; it means the process cannot serve requests correctly. Liveness failure triggers a restart; readiness failure triggers a drain. Restarting every machine on a Redis outage produces a thundering herd on recovery — the wrong response to a shared-store failure.

### 5. Application-level resilience on failover

Every outbound call — to a backing service (Redis, Postgres) or a sibling service — uses:

- Exponential backoff with jitter on transient failures (`context.DeadlineExceeded`, connection refused, `redis.Nil` where a value is expected, `pgx.ErrNoRows` where a value is expected)
- A bounded retry ceiling (≤3 attempts for read paths; ≤1 for write paths that are not idempotent)
- A circuit breaker for outbound HTTP to sibling services, so a downstream outage does not cascade into caller resource exhaustion

The failure mode this closes: during a Postgres primary failover, writes fail for a bounded window (seconds). Retries with backoff absorb that window; a service without retries surfaces the failover as a user-visible error.

### 6. Multi-region deployment is architecturally compatible but has documented follow-up dependencies

A single-region deployment with all requirements above satisfies the "no application-controllable SPOFs" bar within that region. Regional failure tolerance is a separate concern — regional loss remains a SPOF at the region level, and this ADR does not mandate multi-region.

Multi-region *is* architecturally compatible with this design: services are stateless behind the load balancer, adapter selection is env-var driven, and Fly's routing infrastructure (`primary_region` + `[[regions]]`) supports it operationally. However, two application-level dependencies must be closed before an actual multi-region deployment. Each becomes a follow-up ADR when multi-region is warranted:

- **Cross-region JWKS distribution.** `auth-server` sources signing keys from per-process env vars (`AUTH_JWT_RSA_PRIVATE_KEY_PEM`, `_NEXT`, `_PREVIOUS`). Key rotation is env-var-and-restart per machine, so during a rotation window one region can hold a `_NEXT` key that another does not. Verifiers (`token-introspection-service`, `example-resource-service`) fetch JWKS from a region-local `auth-server`, so a token signed in one region can fail verification in another for the duration of a mid-rotation window. Correctness depends on operator discipline (careful `_PREVIOUS`/`_NEXT` overlap during rotation), not on the design. A future ADR must move key material to a shared source (a shared secrets store, a JWKS-signing service, or a Redis-backed key distribution channel) so rotation propagates atomically across regions.

- **Cross-region refresh-token reuse-detection consistency.** [ADR-0014](0014-refresh-token-rotation-replay.md) rotates refresh tokens on every use (delete-old, insert-new). Under strongly-consistent single-primary Redis this is race-free. Under eventually-consistent globally-replicated Redis (e.g. Upstash Global's default) two concurrent uses of the same refresh token in different regions can both delete-and-issue before the delete propagates — the reuse-detection window has a silent blind spot, and a stolen refresh token can be spent twice. A future ADR must either mandate a strongly-consistent Redis topology for the refresh-token keyspace (Redis Cluster with per-shard consistency; a single primary with regional read caching) or move reuse detection to Postgres.

Neither dependency affects single-region deployment. Both are known blockers for multi-region and are named here so a reader considering multi-region has an explicit list rather than a surprise. Fly's `primary_region` + `[[regions]]` block, Upstash Global, and Fly Managed Postgres HA remain the recommended deployment primitives when multi-region is warranted, subject to closing the two dependencies above.

## Files Changed

| File | Change |
|---|---|
| `README.md` — Horizontal Scalability section | Rewrites the target statement to "no SPOFs required in production," documents the startup guard and readiness gate as commitments, and adds the HA-mode backing-service table |
| `CLAUDE.md` — Horizontal Scalability Constraints | Points to this ADR as the authoritative source; ADR table gains a row for 0029 |
| `docs/adr/0006-redis-token-storage.md` | Cross-references this ADR from its Consequences section; the "mitigated by Sentinel" language becomes mandatory, not optional |
| `docs/adr/0007-postgresql-relational-data.md` | Cross-references this ADR from its Consequences section; the "mitigated by HA" language becomes mandatory, not optional |
| Each service's `internal/container/container.go` | Adds the startup guard described in §3 (separate implementation change; this ADR specifies the requirement) |

## Consequences

**Positive**

- The platform can be scaled beyond N=1 without silent state corruption. This is now enforced by the startup guard, not by operator discipline.
- Single-machine failure at any layer (application replica, Redis primary, Postgres primary) does not cause an outage. Recovery is bounded by failover time (seconds) rather than by the time to human intervention (minutes to hours).
- The reference implementation teaches production-grade patterns — health-check gating, retry-with-backoff, HA backing stores — rather than accepting SPOFs and deferring them to the "deployment layer."
- The rollout of Q2's fatal-in-production guard is subsumed by this ADR: silent memory fallbacks in production are the class of bug this design eliminates.

**Negative / Trade-offs**

- Production deployment cost increases. HA-mode Fly Managed Postgres is more expensive than a single-primary instance; Upstash Global costs more than Upstash regional. N=2 machines per service doubles per-service compute.
- Local development is unchanged (ADR-0004 preserved), but any environment that intends to *look* like production (a shared staging, an acceptance-suite compose file with `AUTH_LOG_ENVIRONMENT=production`) must now provide durable state or the services will refuse to start. The acceptance suite already brings up a Redis container per run, so this is compatible.
- Multi-region readiness is a design property, not a deployed capability. Deploying multi-region requires provisioning multi-region backing stores and adding a `[[regions]]` block to each `fly.<service>.toml` — separate operational work, not covered here.

## Alternatives Considered

- **Keep the SPOF-acceptance stance from ADR-0004/0006/0007.** Rejected: contradicts the stated goal of reliable horizontal scalability. A reference implementation whose reference value is horizontal scalability cannot ship with documented SPOFs at every state layer.
- **Delete the in-memory adapters entirely and require Redis + Postgres in every environment, including local dev.** Rejected: breaks ADR-0004's zero-external-dependencies contract for `go run ./cmd/serve.go` and for contributors who work on one service at a time. The startup guard achieves the same production-safety outcome without changing the local-dev story.
- **Require multi-region deployment as part of "no SPOFs".** Rejected: unnecessarily prescriptive. A regional outage is a SPOF at the region level, but a well-instrumented single-region deployment with HA-mode backing stores and N≥2 replicas satisfies the "no application-controllable SPOF" bar. Multi-region is supported by design (see §6) and can be adopted incrementally.
- **Introduce a separate `AUTH_REQUIRE_DURABLE_STATE` variable per service instead of keying on `*_LOG_ENVIRONMENT`.** Rejected as the default; the `LOG_ENVIRONMENT` variable is already set to `production` in the Fly configs and already gates other production-shaped behavior. A separate variable is acceptable if a test environment needs to opt out of the guard while running under a `production` log format — this is a per-environment override, not the default.
