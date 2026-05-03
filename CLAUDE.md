# Identity Platform Go — Claude Context

## What This Project Is

A **reference implementation** of OAuth 2.0 / OIDC in Go. Its purpose is to demonstrate clean architecture and extensible design — not to be a production identity provider. Decisions that look like shortcuts (in-memory storage, stubbed grant types) are intentional. Do not treat them as bugs or incomplete work.

---

## OAuth 2.0 Domain Context

This codebase implements specific RFCs. Understand the semantics before modifying anything that touches tokens, clients, or grant types.

### Implemented

| RFC | What it governs | Where implemented |
|-----|----------------|-------------------|
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | OAuth 2.0 core — token endpoint, grant types, error responses | `services/auth-server` — `client_credentials` only; `authorization_code` is a stub |
| [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) | Bearer token usage — `Authorization: Bearer` header format, `WWW-Authenticate` error params, `insufficient_scope` error | `services/example-resource-service/internal/adapters/inbound/http/middleware.go` |
| [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) | Token revocation | `services/auth-server` |
| [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) | Token introspection | `services/auth-server`, `services/token-introspection-service` |
| [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068) | JWT profile for access tokens — `scope` as space-delimited string, `client_id` claim | `services/auth-server/internal/application/token_service.go` |

### Planned (not yet implemented)

These RFCs are on the roadmap toward a complete auth/authz system. Do not implement them ad hoc — each requires an ADR before work begins.

| RFC | What it adds | Key design notes |
|-----|-------------|-----------------|
| [RFC 7521](https://datatracker.ietf.org/doc/html/rfc7521) / [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) | Assertion Framework / JWT Bearer Grants — clients authenticate using a signed JWT instead of a client_secret | Enables service-to-service federation where a client proves identity with a private key. Requires JWKS (RFC 7517) to be in place first so the auth-server can retrieve the client's public key for assertion verification. |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | PKCE — `code_challenge` / `code_verifier` | Parameters already parsed in `handler.go` and stored in `GrantRequest.CodeVerifier`; validation is the missing piece. Required before `authorization_code` can be considered complete. |
| [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) | JSON Web Key Sets — `/.well-known/jwks.json` | Enables RS256 signing so resource servers can verify tokens without sharing the signing secret. Currently all signing is HS256 with a shared key. |
| [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) | JSON Web Algorithms — defines `RS256`, `HS256`, etc. | Governs valid `alg` values in JWTs. Becomes relevant when JWKS/RS256 support is added. |
| [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) | Dynamic Client Registration | Standardizes the `client-registry-service` API. Any OAuth2-aware tool can register clients without custom integration. |
| [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) | Authorization Server Metadata — `/.well-known/oauth-authorization-server` | Required for OAuth2 client libraries to auto-configure. Without it, every consumer must be manually pointed at each endpoint. |
| [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) | DPoP — Demonstrating Proof of Possession | Binds access tokens to the client's private key, so a stolen token cannot be replayed from a different client. Requires JWKS (RFC 7517) and changes the token endpoint to accept a `DPoP` header. High implementation cost; most valuable when tokens are long-lived or carried over untrusted channels. |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | `id_token`, `/userinfo` endpoint, `nonce`, `openid` scope, authentication context | Bridges the gap between authorization and authentication. The `identity-service` does user auth but does not issue identity tokens. OIDC is what makes this an authentication system, not just an authorization one. |

### Considered (lower priority)

These are valid for a complete auth/authz system but have narrower applicability. Implement after the Planned items above are stable.

| RFC | What it adds | Key design notes |
|-----|-------------|-----------------|
| [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) | Device Authorization Flow — browserless devices (CLIs, IoT) | Adds a new grant type (`urn:ietf:params:oauth:grant-type:device_code`) and a `POST /device_authorization` endpoint. Follows the same Strategy pattern extension point as other grant types. |
| [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) | Token Exchange — a service impersonates a user or delegates to another service | Useful in service-mesh / zero-trust scenarios. Adds a new grant type (`urn:ietf:params:oauth:grant-type:token-exchange`) with `subject_token` and `actor_token` parameters. |
| [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207) | Authorization Server Issuer Identification — adds `iss` to authorization responses | Prevents mix-up attacks when a client interacts with multiple authorization servers. Low cost to implement; high value if this platform ever runs multiple issuers. |

### Out of scope

| RFC | Reason |
|-----|--------|
| [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) — mTLS Client Authentication | Infrastructure-level concern beyond the reference implementation's scope |

### Key OAuth2 Invariants — Do Not Break These

- **Introspection always returns HTTP 200**, even for invalid or expired tokens. An invalid token must return `{"active": false}`, never a 4xx error. This is required by RFC 7662 §2.2.
- **Token revocation is idempotent**. Revoking an already-revoked token must return 200. RFC 7009 §2.2.
- **`Cache-Control: no-store`** must be set on all token endpoint responses. RFC 6749 §5.1.
- **Scope resolution**: requested scopes are intersected with the client's allowed scopes — never grant more than the client is registered for.
- **Secret comparison uses `subtle.ConstantTimeCompare`** to prevent timing attacks. Do not replace this with `==`.
- **`error_uri` is intentionally omitted** from all OAuth2 error responses. RFC 6749 §5.2 defines it as optional. This implementation does not maintain a human-readable error catalogue, so the field is left out rather than providing a stub URL.
- **`unsupported_token_type`** is the correct error code when a caller requests revocation or introspection for a token type the server does not recognise (RFC 7009 §2.2). The `unsupported_token_type` constant is defined in the auth-server handler alongside the other OAuth error codes. Currently only `access_token` is supported; `refresh_token` and other hint values are accepted as no-ops (the hint is logged and ignored) per RFC 7009 §2.1's guidance that hints are purely advisory.
- **Signing key entropy**: all signing key env vars (`AUTH_JWT_SIGNING_KEY`, `INTROSPECT_JWT_SIGNING_KEY`, `RESOURCE_JWT_SIGNING_KEY`) must be set to at least 32 bytes of cryptographically random data. Generate with `openssl rand -hex 32`. A short or guessable key allows any party to forge tokens — this is a complete authentication bypass.

### Grant Types

Only `client_credentials` is fully implemented. `authorization_code` and `refresh_token` are intentional stubs — their `GrantStrategy` implementations exist as extension points, not forgotten work.

**To add a new grant type:**
1. Add a constant to `services/auth-server/internal/domain/grant.go`
2. Implement `GrantStrategy` in `services/auth-server/internal/application/grant_strategy.go`
3. Register it in `services/auth-server/internal/container/container.go`

Nothing else needs to change — the `GrantStrategyRegistry` dispatches by `Supports()` match.

---

## Architecture Constraints

All services follow **Ports and Adapters (Hexagonal Architecture)**. The dependency direction is strict and must not be violated:

```
domain  →  application  →  ports  →  adapters
```

- `domain` has **no external imports** — no framework, no HTTP, no logging
- `application` depends only on domain interfaces — never on adapter implementations
- HTTP handlers live in `adapters/inbound/http` and depend on port interfaces, not application types directly
- In-memory repositories live in `adapters/outbound/memory`

**If you find yourself importing an adapter package from the domain or application layer, stop.** That is an architecture violation.

### Dependency Injection

Each service wires everything in `internal/container/container.go`. This is the only place where concrete implementations are instantiated and injected. Use constructor injection — no service locator, no global state.

### Inter-Service Communication

Services communicate via HTTP using outbound port adapters in `internal/adapters/outbound/<service-name>/`. Each call site is behind an interface, so adapters can be swapped without touching business logic.

| Caller | Dependency | Port | Adapter | Env var |
|--------|-----------|------|---------|---------|
| `auth-server` | `client-registry-service` | `ports.ClientAuthenticator` | `adapters/outbound/clientregistry` | `AUTH_CLIENT_REGISTRY_URL` |
| `auth-server` | `identity-service` | `ports.UserAuthenticator` | `adapters/outbound/identityservice` | `AUTH_IDENTITY_SERVICE_URL` |
| `example-resource-service` | `token-introspection-service` | `ports.TokenIntrospector` | `adapters/outbound/introspection` | `RESOURCE_INTROSPECTION_URL` |
| `example-resource-service` | `authorization-policy-service` | `ports.PolicyChecker` | `adapters/outbound/policy` | `RESOURCE_POLICY_URL` |

**Fallback behaviour**: when an env var is empty, the service falls back to an in-memory adapter (or local JWT validation/scope-only access control). This lets individual services run in isolation during development without the full stack.

**Two-layer authorization in `example-resource-service`**: scope validates token capability (can this token perform reads/writes?); policy validates subject permission (is this specific user/client allowed?). Scope check is local and free; policy check is an outbound HTTP call. When `RESOURCE_POLICY_URL` is unset, scope alone gates access — the policy layer is opt-in.

### Horizontal Scalability Constraints

All services are stateless at the HTTP layer and can be scaled horizontally. **The bottleneck is the in-memory persistence layer**: each replica has an independent copy of its data, making multi-instance deployments functionally incorrect for write operations. Before scaling beyond one replica, replace the in-memory adapter for that service with a durable, shared-state adapter (PostgreSQL, Redis, etc.). The compile-time interface checks on every memory adapter (`var _ domain.XRepository = (*XRepository)(nil)`) mark the exact swap point — see [ADR-0005](docs/adr/0005-adapter-scalability-contract.md).

**Policy evaluation caching**: `authorization-policy-service` wraps `PolicyService` with a `CachingPolicyEvaluator` (Redis, 60-second TTL) when `POLICY_REDIS_URL` is set. The cache key is `authz:{subject_id}:{resource}:{action}`. The decorator fails open on Redis errors — evaluation always falls through to the database. Role mutations do not invalidate the cache; a subject's effective permissions may lag up to 60 seconds after a role change. This is acceptable for the reference implementation; production deployments should call `DEL authz:{subject_id}:*` on role mutation.

---

## Intentional Design Decisions

These exist for documented reasons. Do not change them without reading the relevant ADR.

| Decision | Why | ADR |
|----------|-----|-----|
| All persistence is in-memory | Reference implementation — makes it runnable with zero dependencies | [ADR-0004](docs/adr/0004-in-memory-persistence-for-reference.md) |
| Compile-time interface checks on every memory adapter | Catches interface drift at declaration site; marks the swap point for durable adapters | [ADR-0005](docs/adr/0005-adapter-scalability-contract.md) |
| Strategy pattern for grant types | Open/closed — add grant types without modifying dispatch logic | [ADR-0003](docs/adr/0003-use-strategy-pattern-for-grants.md) |
| Go Workspaces monorepo | Independent versioning per module while sharing local code | [ADR-0002](docs/adr/0002-use-go-workspaces.md) |
| Hexagonal architecture | Business logic stays framework-agnostic and independently testable | [ADR-0001](docs/adr/0001-use-ports-and-adapters.md) |

---

## Build & Test

```bash
task test          # all tests (unit + integration)
task test:unit     # unit tests only (race detection + coverage)
task test:integration
task lint          # golangci-lint across all modules
task build         # compiles all services to bin/
task swagger       # regenerates OpenAPI docs
task tidy          # go work sync + tidy all modules
```

Tests use **manual mocks** (no mock generator). Mocks implement domain interfaces directly in `_test.go` files. Use table-driven tests for variations.

Tag-based filtering: `go test -tags unit` or `go test -tags integration`.

**Go workspace tooling pattern** — tools that don't understand workspaces must be run per-module:

```bash
find . -name "go.mod" -not -path "*/vendor/*" | while read modfile; do
  dir=$(dirname "$modfile")
  (cd "$dir" && <command>) || exit 1
done
```

---

## Shared Libraries

Located in `libs/`. Each is an independent Go module. The dependency graph flows one way:

```
libs/errors  ←  libs/httputil, libs/logging, libs/testutil, libs/jwtutil  ←  all services
```

A change to `libs/errors` cascades to every service at release time.

| Library | Purpose |
|---------|---------|
| `libs/errors` | Typed `AppError` with `ErrorCode` and HTTP status mapping |
| `libs/httputil` | `WriteJSON`, `WriteError` — always buffer before writing headers |
| `libs/logging` | `slog`-based structured logging with trace ID and context support |
| `libs/testutil` | Shared test helpers |
| `libs/jwtutil` | Canonical `Claims` type, `Sign`, `Parse`, and `NewClaims` — the single source of truth for JWT structure across auth-server and token-introspection-service |

---

## Versioning & Releases

Each service and library versions independently. Releases are triggered automatically on merge to `main` via Conventional Commits:

- `feat:` → minor bump
- `fix:`, `perf:`, `refactor:` → patch bump
- `feat!:` or `BREAKING CHANGE:` footer → major bump
- `chore:`, `docs:`, `style:`, `ci:`, `test:` → no release

When `libs/errors` is released, all downstream libraries and services are also released automatically (dependency propagation).
