# Comparison: Identity Platform vs SUN Auth Gateway

This document compares the identity-platform-go architecture against the SUN Auth Gateway — the production API key authorization and usage-tracking platform at The Weather Company. The comparison is intended to surface architectural gaps, performance trade-offs, and specifically to evaluate whether this platform addresses known provisioning problems in the SUN gateway's Cassandra-backed authorizer.

## What each system does

| Dimension | SUN Auth Gateway | identity-platform-go |
|---|---|---|
| **Primary model** | Proprietary API key + product-based authorization | Standard OAuth 2.0 (RFC 6749 / 7662 / 7009) |
| **Token format** | Opaque UUID API key passed as a query parameter | JWT Bearer token in `Authorization` header |
| **Authorization check** | 3-check: key exists → not throttled → has product access for this path+method | 2-check: JWT signature valid → not expired or revoked |
| **Key/client store (production)** | Cassandra (`sun-ms-auth-authorizer`, namespace `authorizer-le`) | PostgreSQL via pgxpool |
| **Key/client store (dev/QA)** | MongoDB (`sun-auth-authorizer`, actively developed replacement) | In-memory (sync.RWMutex) |
| **Rate limiting** | Full plan evaluation engine: CronJob → Redis lastused scan → PostgreSQL limitrule → throttle push to authorizer | Not implemented |
| **Usage tracking** | Async Kafka pipeline (Akamai DataStream2 → MSK → Consumer → MongoDB Atlas time-series) | Not implemented |
| **Request routing** | Hystrix circuit-breaker-wrapped dispatch to 59+ named backend services | Reverse-proxy (api-gateway only) |
| **ESI aggregation** | Controller generates ESI markup for Akamai to resolve multi-product responses | Not applicable |
| **Language** | Scala (router, controller, user-mgt) + Go (authorizer, accounting) | Go throughout |
| **Key provisioning writer** | User Management service → background job → Authorizer Admin API → Cassandra/MongoDB | Client Registry Service → synchronous PostgreSQL write |

---

## The Cassandra provisioning problem

The SUN production authorizer runs against Cassandra (the `sun-ms-auth-authorizer` service, v1.7.0-RC5). A MongoDB-backed replacement (`sun-auth-authorizer`, approaching v3.0.0) is in development and validated in dev/QA, but has not yet reached production. The Cassandra variant has well-documented provisioning problems; this platform's design directly addresses several of them.

### Problem 1: Post-provisioning 401 window

**SUN behavior:** API key creation in User Management triggers an `apikey_authorized` background job. That job calls the Authorizer Admin API, which writes to Cassandra. Cassandra uses quorum writes — the write is acknowledged when a quorum of replicas agrees, but non-quorum replicas may not have the data yet. Requests that hit an un-caught-up replica return 401 even though the key was successfully provisioned. Depending on background job scheduling and Cassandra replication lag, this window can be seconds to minutes.

**This platform's behavior:** `POST /clients` on the client-registry-service is a synchronous PostgreSQL write wrapped in an ACID transaction. The HTTP 201 response means the client is immediately queryable by all readers on the same primary. There is no background job, no replication window, and no intermediate service hop. The key is available the instant the response is returned.

### Problem 2: Tombstone accumulation from product updates

**SUN behavior:** The `PUT /authadmin/service` endpoint replaces all products for a key — it deletes all existing `apikey_products` documents then inserts the new set. In Cassandra, deletes become tombstones that accumulate in SSTables. Under high write/update frequency (plan evaluations, product grants, key rotations), tombstone count grows and degrades read performance on the authorization hot path. Manual compaction is required.

**This platform's behavior:** PostgreSQL `DELETE` + `INSERT` inside a transaction leaves no tombstones. Vacuuming is handled automatically by `autovacuum`. The client registry stores scopes as a `TEXT[]` column — a single-row update replaces all values atomically with no dead-row accumulation beyond what `autovacuum` handles.

### Problem 3: Throttle state propagation race

**SUN behavior:** When the plan evaluator throttles a key, it pushes `throttledUntil` to the Authorizer via an admin HTTP call. The Authorizer writes it to Cassandra. Until Cassandra replication settles, some replicas may still authorize the throttled key.

**This platform's behavior:** This platform has no throttle concept — rate limiting is not implemented. If rate limiting were added, the natural implementation would be a Redis `SET` with TTL (the same approach used for token revocation), which achieves immediate consistency across all replicas that share the same Redis instance.

### Problem 4: No native token expiry

**SUN behavior:** API keys do not expire by design — they persist until explicitly deleted. Throttle state has a `throttledUntil` timestamp checked at request time. There is no automatic expiry mechanism; cleanup requires explicit User Management calls.

**This platform's behavior:** JWTs carry an `exp` claim validated on every request with no database lookup. Refresh tokens are stored in Redis with a TTL — they expire and are garbage-collected automatically. Revoked tokens are deleted from Redis immediately and are then invisible to all replicas.

### What this platform does NOT address

- The underlying **async background job architecture** in SUN is the root cause of the provisioning window, not Cassandra specifically. The MongoDB migration shortens the window (stronger consistency than Cassandra) but does not eliminate it. Eliminating the window requires making provisioning synchronous — which is this platform's approach.
- SUN's **multi-hop provisioning path** (UI/ServiceNow → User Management → background job → Authorizer → database) exists because User Management is the sole authority for key state and the Authorizer is a read-optimized cache of that state. This platform collapses those layers: the client registry IS the authorizer's source of truth.

---

## Feature gaps

### Features in SUN not present here

| Feature | SUN implementation | Gap in this platform |
|---|---|---|
| Rate limiting and plan evaluation | CronJob-triggered evaluator, Redis lastused scan, PostgreSQL limitrule, throttle push | Not implemented |
| Usage tracking | Akamai DataStream2 → Kafka → MongoDB Atlas time-series; 4 granularities (minute/hour/day/month) | Not implemented |
| Product-based authorization | Per-key product records (`apikey_products`) controlling which paths+methods a key may call | OAuth scopes are coarser-grained; no path+method tuples |
| ESI aggregation | Controller generates `<esi:include>` markup for Akamai multi-product responses | Not applicable |
| Green Cookie / provenance validation | Router validates an Akamai-injected cookie before any auth check | Not applicable |
| Hystrix circuit breakers | Every backend call wrapped; open circuit returns 503 | No circuit breaker |
| Multi-region deployment | 6 PE Gateway EKS clusters across 4 AWS regions | Single-cluster reference |
| Location look-aside | Controller resolves geocode/postal/placeid via Location Service V3 before dispatch | Not applicable |
| Legacy aggregate path expansion | Shortcode → canonical path mapping before authorization | Not applicable |

### Features here not present in SUN

| Feature | This platform | SUN gap |
|---|---|---|
| OAuth 2.0 compliance | RFC 6749 token issuance, RFC 7662 introspection, RFC 7009 revocation | Proprietary API key model; no standard OAuth |
| JWT Bearer tokens | HMAC-SHA256 signed, self-validating, carry scopes/roles/permissions | Opaque UUIDs require database roundtrip for every auth check |
| Token revocation | Redis DEL + TTL; immediate across all replicas | No revocation; max-age cache expiry only (up to 1 hour) |
| RBAC policy evaluation | Dedicated authorization-policy-service; `{subject, resource, action}` → allow/deny | Binary product access; no role hierarchy |
| Clean hexagonal architecture | Ports & Adapters across all services; domain has zero infrastructure dependencies | Mixed concerns; Scala Play/HTTP4s monoliths with embedded business logic |
| Synchronous provisioning | Client creation is a single ACID transaction; immediately consistent | Async background job chain; provisioning window exists |
| Authorization Code grant | Stub present; designed for extension | Not applicable (API key model) |
| Adapter swap contract | ADR-0005: compile-time interface checks enforce the swap point | No equivalent; database migration requires code changes |

---

## Performance and scaling

### Authorization hot path (every API request)

| | SUN (Cassandra prod) | SUN (MongoDB dev/QA) | This platform |
|---|---|---|---|
| Lookup mechanism | Cassandra CQL quorum read | MongoDB indexed document query | JWT: no DB lookup (signature + exp claim only); introspection: Redis O(1) GET |
| Consistency | Eventual (QUORUM) | Strong (primary read) | Immediate (stateless JWT or Redis) |
| Estimated p99 latency | 2–5ms (network + quorum negotiation) | 1–3ms | JWT: <0.1ms (in-process); Redis: <1ms |
| Horizontal read scaling | Cassandra nodes scale reads linearly | MongoDB replica set; reads from secondaries | JWT needs no scaling; Redis Cluster for token introspection |

SUN mitigates Cassandra read latency by caching authorization decisions via `max-age` / `cacheduration` (up to 1 hour). The authorizer is hit far less often than raw request volume would suggest. This platform's JWT model eliminates the database roundtrip entirely for access token validation — the JWT is self-validating.

### Provisioning write path

| | SUN (Cassandra prod) | SUN (MongoDB dev/QA) | This platform |
|---|---|---|---|
| Mechanism | UserMgt → background job → Admin API → Cassandra | UserMgt → background job → Admin API → MongoDB | HTTP POST → PostgreSQL ACID commit |
| Hops | 3+ (job scheduler → HTTP → Cassandra) | 3+ (job scheduler → HTTP → MongoDB) | 1 (HTTP → PostgreSQL) |
| Consistency | Eventual (replica lag) | Strong (primary write) | Immediate (ACID transaction) |
| Failure mode | Job fails → key in limbo; restart CronJob required | Job fails → retry via backgroundwork table | Transaction rollback → client retries the same HTTP call |
| Provisioning window | Seconds to minutes | Seconds | Zero |

### Throughput ceiling

**SUN** is designed for tens of millions of API requests per day across 6 global clusters. The Kafka accounting pipeline (500 partitions, 5-consumer group, 15-consumer HPA) handles usage telemetry at that scale asynchronously. Authorization decisions are cached, so the Cassandra/MongoDB tier receives a small fraction of total request volume.

**This platform** has no Kafka equivalent. If deployed at SUN's request volume, the PostgreSQL client registry would become the bottleneck unless read replicas and a caching layer (equivalent to SUN's `max-age`) were added. For the reference workloads this platform is designed for, PostgreSQL + Redis is more than sufficient and operationally simpler.

### Language and runtime overhead

| | SUN router/controller/user-mgt | SUN authorizer/accounting | This platform |
|---|---|---|---|
| Language | Scala 2.11–2.13 on JVM | Go | Go |
| Startup time | 15–30 seconds (JVM warmup, class loading) | <1 second | <1 second |
| Memory footprint | 4–6 GiB per JVM service (heap + off-heap) | 64–128 MiB per Go service | 32–128 MiB per service |
| GC behavior | G1GC, manual collection every 5 min (controller) to mitigate OOMKilled | Go GC (low latency, sub-millisecond pauses) | Go GC |
| Cold start (Kubernetes pod) | Slow; startup probes allow 60 failures × 5s = 5 minutes | Fast | Fast |

The JVM services in SUN carry significant operational overhead. The controller requires `-Xms6g -Xmx6g` and manual GC calls every 5 minutes to avoid `OOMKilled`. User Management requires `-Xms2g -Xmx2g` with Akka HTTP timeouts tuned to 180-second request timeout. This platform's Go services start in under a second and require no JVM tuning.

---

## Architectural recommendations

Based on this comparison, the following changes to SUN's architecture would eliminate the Cassandra provisioning problems without requiring a full rewrite:

1. **Make provisioning synchronous.** The background job pattern (`apikey_authorized`) exists because User Management and the Authorizer are separate services with separate databases. If the Authorizer's write path were synchronous from User Management (blocking the HTTP response until the authorizer confirms the write), the provisioning window would disappear. The MongoDB migration enables this — MongoDB's strong consistency means a synchronous push would be reliable, unlike Cassandra's eventual consistency.

2. **Replace Cassandra with Redis for throttle state.** Throttle state (`throttledUntil`) is a perfect Redis use case: it is a single value per key, it has a natural TTL, and it needs to be immediately consistent across replicas. Storing it in Redis instead of Cassandra eliminates tombstones and replication lag for the throttle check.

3. **Cache authorization decisions in Redis, not Cassandra.** SUN already caches via Akamai's `max-age`. Adding an in-process or Redis cache at the authorizer level (keyed by `apiKey + path + method`, TTL = `cacheduration`) would reduce Cassandra/MongoDB read pressure to near zero, making the choice of backing store largely irrelevant for steady-state performance.

4. **Consider JWT for internal service-to-service calls.** The router currently calls the authorizer on every request. If the authorizer returned a short-lived JWT on the first check (instead of an opaque max-age), subsequent requests within that window would be validated in-process without a network call — the same model this platform uses for resource service access.

---

## Related documentation

- [ADR-0006: Redis Token Storage](adr/0006-redis-token-storage.md) — rationale for using Redis for token state in this platform
- [ADR-0007: PostgreSQL for Relational Data](adr/0007-postgresql-relational-data.md) — rationale for PostgreSQL client registry
- [ADR-0005: Adapter Scalability Contract](adr/0005-adapter-scalability-contract.md) — how adapter swap points are enforced
- [Bearer JWT Tokens](auth-mechanisms/bearer-jwt-tokens.md) — JWT auth mechanism detail
- [SUN Auth Gateway architecture](https://github.com/TheWeatherCompany/sun-architecture/tree/main/teams/jetstream/auth) — full C4 diagrams and service documentation
