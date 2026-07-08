# Identity Platform Go — Claude Context

## What This Project Is

A **reference implementation** of OAuth 2.0 / OIDC in Go. Its purpose is to demonstrate clean architecture and extensible design — not to be a production identity provider. Decisions that look like shortcuts (in-memory storage, stubbed grant types) are intentional. Do not treat them as bugs or incomplete work.

---

## Extracted services

The following sibling services were originally hosted in this repository and have since been moved to their own repositories under `jedi-knights/`. They are listed here so future readers know where to find them and so the references in older commits / docs make sense:

| Service | Now lives at | Why it was extracted |
|---|---|---|
| `api-gateway` | [github.com/jedi-knights/api-gateway](https://github.com/jedi-knights/api-gateway) | Generic reverse-proxy + middleware infrastructure (rate limiting, circuit breaking, retries, caching, MCP routing). Not OAuth-specific; reusable across projects. |

When using `docker-compose.yml` to bring up the platform, the gateway entry has been removed. Clone the gateway's repo separately and point its routes at the service ports exposed by this compose file (9080–9085).

---

## OAuth 2.0 Domain Context

This codebase implements specific RFCs. Understand the semantics before modifying anything that touches tokens, clients, or grant types.

### Implemented

| RFC | What it governs | Where implemented |
|-----|----------------|-------------------|
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | OAuth 2.0 core — token endpoint, grant types, error responses | `services/auth-server` — `client_credentials`, `refresh_token`, and `authorization_code` are all fully implemented |
| [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) | Bearer token usage — `Authorization: Bearer` header format, `WWW-Authenticate` error params, `insufficient_scope` error | `services/example-resource-service/internal/adapters/inbound/http/middleware.go` |
| [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) | Token revocation | `services/auth-server` |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | PKCE — `code_challenge` / `code_verifier` | `services/auth-server`, [ADR-0009](docs/adr/0009-authorization-code-pkce.md). Mandatory S256 for every client; `plain` is rejected. |
| [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) | JSON Web Key Sets — `/.well-known/jwks.json` | `services/auth-server`, [ADR-0008](docs/adr/0008-rs256-jwks-token-signing.md). RS256 by default with a `_PREVIOUS`/`_NEXT` key-rotation window; HS256 remains available as a migration fallback. |
| [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) | JSON Web Algorithms — defines `RS256`, `HS256`, etc. | `services/auth-server`, [ADR-0008](docs/adr/0008-rs256-jwks-token-signing.md). Algorithm-confusion defence (RFC 8725 §3.1) enforced by `jwtutil.ParseRS256` — HS256-signed tokens are rejected outright under RS256 config. |
| [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) | Dynamic Client Registration | `services/client-registry-service`, [ADR-0013](docs/adr/0013-dynamic-client-registration.md) |
| [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) | Token introspection | `services/auth-server`, `services/token-introspection-service` |
| [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) | Authorization Server Metadata — `/.well-known/oauth-authorization-server` | `services/auth-server`, [ADR-0012](docs/adr/0012-authorization-server-metadata.md) |
| [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) | Token Exchange | `services/auth-server`, [ADR-0016](docs/adr/0016-token-exchange-rfc-8693.md) |
| [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068) | JWT profile for access tokens — `scope` as space-delimited string, `client_id` claim | `services/auth-server/internal/application/token_service.go` |
| [RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396) | Rich Authorization Requests — `authorization_details` | `services/auth-server`, [ADR-0017](docs/adr/0017-rich-authorization-requests-rfc-9396.md). Per-type schema validation for `mcp_tool` and `resource`. |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | `id_token`, `/userinfo` endpoint, `nonce`, `openid` scope, authentication context | `services/auth-server`, `services/identity-service`, [ADR-0010](docs/adr/0010-oidc-core.md) |
| [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207) | Authorization Server Issuer Identification — `iss` on every authorization response | `services/auth-server`, `services/login-ui`, [ADR-0020](docs/adr/0020-authorization-server-issuer-identification.md). Value is `cfg.JWT.Issuer`, echoed on both the direct error-redirect path and login-ui's post-login success redirect. |

### Planned (not yet implemented)

These RFCs are on the roadmap toward a complete auth/authz system. Do not implement them ad hoc — each requires an ADR before work begins.

| RFC | What it adds | Key design notes |
|-----|-------------|-----------------|
| [RFC 7521](https://datatracker.ietf.org/doc/html/rfc7521) / [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) | Assertion Framework / JWT Bearer Grants — clients authenticate using a signed JWT instead of a client_secret | Enables service-to-service federation where a client proves identity with a private key. JWKS (RFC 7517) is now in place, so the main remaining work is the assertion-verification grant strategy itself. |
| [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) | DPoP — Demonstrating Proof of Possession | Binds access tokens to the client's private key, so a stolen token cannot be replayed from a different client. JWKS (RFC 7517) is now in place; remaining work is accepting and validating a `DPoP` header at the token endpoint. High implementation cost; most valuable when tokens are long-lived or carried over untrusted channels. |

### Considered (lower priority)

These are valid for a complete auth/authz system but have narrower applicability. Implement after the Planned items above are stable.

| RFC | What it adds | Key design notes |
|-----|-------------|-----------------|
| [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) | Device Authorization Flow — browserless devices (CLIs, IoT) | Adds a new grant type (`urn:ietf:params:oauth:grant-type:device_code`) and a `POST /device_authorization` endpoint. Follows the same Strategy pattern extension point as other grant types. |

### Out of scope

| RFC | Reason |
|-----|--------|
| [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) — mTLS Client Authentication | Infrastructure-level concern beyond the reference implementation's scope |

### Platform extensions beyond the OAuth2/OIDC spec

A few ADRs add platform-specific behavior that isn't governed by an RFC — worth knowing about when scoping test coverage, since they layer on top of the specs above rather than replacing them: [ADR-0015](docs/adr/0015-agent-principal-type.md) (agent principal type — distinguishes AI-agent clients from human/service clients, referenced by RAR's `mcp_tool` authorization details), [ADR-0018](docs/adr/0018-agent-audit-event-schema.md) (agent audit event schema), and [ADR-0019](docs/adr/0019-usage-accounting-and-billing.md) (usage accounting and billing).

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

`client_credentials`, `refresh_token`, and `authorization_code` (with mandatory PKCE-S256, per [ADR-0009](docs/adr/0009-authorization-code-pkce.md)) are all fully implemented. See `services/auth-server/CLAUDE.md` for the current per-grant status table and the ADR-0011 login-challenge handoff that `authorization_code` depends on.

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

Each service wires everything in `internal/container/container.go` through `github.com/jedi-knights/go-platform/container`. The platform container exposes:

- `platform.Register[T]` / `platform.RegisterLazy[T]` — register a provider for type `T`. Eager registrations all run during `Bootstrap`; lazy ones run on first `Resolve`. Providers receive `context.Context` for cancellation-aware construction (DB dials, JWKS fetches, etc.).
- `platform.Resolve[T](ctx, c)` / `platform.MustResolve[T](ctx, c)` — fetch a wired value. **Resolution is confined to the composition root (`cmd/serve.go` / `cmd/main.go` and `container_test.go`).** Application code, adapters, and middleware still receive their dependencies as constructor parameters — `Resolve` is not a service locator for business code.
- `c.OnClose(name, fn)` — registered closers run in LIFO during `c.Close(ctx)` and their errors are joined via `errors.Join`. Use this for postgres pools, Redis clients, OTel tracer flushes, etc.
- `c.Bootstrap(ctx)` runs eager providers in **registration order** so an upstream failure surfaces before any downstream provider that depends on it runs (verified by `go-platform` `TestBootstrap_UpstreamErrorBeatsDownstreamMustResolve`).
- `c.Scope()` returns a child container that inherits parent registrations but holds its own. Available but not currently used by any service.

The container's nil-interface contract is supported: a provider that returns `(nil, nil)` for an interface-typed dependency (e.g. an optional `ports.UserAuthenticator` when its upstream URL is unset) resolves to the nil interface without panicking.

`platform.Container` replaces the prior hand-rolled `Container` struct in every service. The convention is unchanged in spirit — wiring is centralized; business code receives dependencies via constructors; no globals — but the mechanics are now uniform across services and provide ordered shutdown, lifecycle channels (`Ready` / `Done`), and a test seam (`OverrideValue`).

#### Per-request scoped values

For request-scoped state — typically a logger enriched with the trace ID and request ID — use **`go-logging`'s context helpers**, not `container.Scope()`:

```go
// In a middleware:
scopedLogger := logger.With("trace_id", traceID, "request_id", requestID)
ctx := logging.WithContext(r.Context(), scopedLogger)
next.ServeHTTP(w, r.WithContext(ctx))

// In a handler:
log := logging.FromContext(r.Context())
log.Info("handled request")
```

`container.Scope()` is reserved for the case where there is a second per-request dependency that depends on the per-request logger (or another per-request scoped value) — e.g., a request-bound database transaction, a per-request cache, or a unit-of-work pattern. No service currently has that pattern; if one is introduced later, that is the natural place to start using `Scope()`. Until then, calling `Scope()` per request would allocate a child container for no observable benefit and would push `Resolve` calls into the request path, violating the "Resolve only at the composition root" rule.

### Inter-Service Communication

Services communicate via HTTP using outbound port adapters in `internal/adapters/outbound/<service-name>/`. Each call site is behind an interface, so adapters can be swapped without touching business logic.

| Caller | Dependency | Port | Adapter | Env var |
|--------|-----------|------|---------|---------|
| `auth-server` | `client-registry-service` | `ports.ClientAuthenticator` | `adapters/outbound/clientregistry` | `AUTH_CLIENT_REGISTRY_URL` |
| `auth-server` | `identity-service` | `ports.UserAuthenticator` | `adapters/outbound/identityservice` | `AUTH_IDENTITY_SERVICE_URL` |
| `example-resource-service` | `token-introspection-service` | `ports.TokenIntrospector` | `adapters/outbound/introspection` | `RESOURCE_INTROSPECTION_URL` |
| `example-resource-service` | `authorization-policy-service` | `ports.PolicyChecker` | `adapters/outbound/policy` | `RESOURCE_POLICY_URL` |
| `login-ui` | `identity-service` | `ports.UserAuthenticator` | `adapters/outbound/identityservice` | `LOGIN_UI_IDENTITY_SERVICE_URL` |
| `login-ui` | `auth-server` | `ports.AuthCodeIssuer` | `adapters/outbound/authserver` | `LOGIN_UI_AUTH_SERVER_URL` + `LOGIN_UI_AUTH_SERVER_SERVICE_TOKEN` |

**Fallback behavior**: when an env var is empty, the service falls back to an in-memory adapter (or local JWT validation/scope-only access control). This lets individual services run in isolation during development without the full stack.

**ADR-0011 login challenge handoff**: `auth-server`'s `/oauth/authorize` validates the OAuth request, persists a `LoginChallenge` (memory or Redis adapter — selected by `AUTH_REDIS_URL`), and 302s to `<AUTH_LOGIN_UI_URL>/sign-in?login_challenge=<id>`. `login-ui` runs sign-in, then calls `auth-server`'s bearer-authed `POST /internal/issue-code` (shared `LOGIN_UI_SERVICE_TOKEN`). `auth-server` atomically Consumes the challenge, mints a code, and returns `{code, redirect_uri, state}` — `login-ui` 302s back to the RP. Both endpoints stay disabled (501 / 404) until the matching env vars are set, so deployments without `login-ui` are unaffected.

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

All shared utility code lives in two external modules — there is no longer a local `libs/` directory. Service `go.mod` files require these directly; no `replace` directives are involved.

| Package | Module | Purpose |
|---------|--------|---------|
| `apperrors` | `github.com/jedi-knights/go-platform/apperrors` | Typed `AppError` with `ErrorCode`; HTTP status mapping lives in `httputil` |
| `jwtutil` | `github.com/jedi-knights/go-platform/jwtutil` | Canonical `Claims` type, `Sign`, `Parse`, `ParseWithAudience`, `ParseWithIssuer`, and `NewClaims` — the single source of truth for JWT structure across auth-server and token-introspection-service. The three `Parse*` functions share an unexported `parseWith` helper in the external module. |
| `httputil` | `github.com/jedi-knights/go-platform/httputil` | `WriteJSON`, `WriteError`, `HTTPStatus`, `TraceIDMiddleware`, `LoggingMiddleware`, `RecoveryMiddleware`. The `Logger` type alias resolves to `go-logging.Logger` (the broader 10-method interface). |
| `testutil` | `github.com/jedi-knights/go-platform/testutil` | Shared test helpers: `NewTestLogger`, `RequireNoError`, `AssertEqual`. The noop logger implements the full 10-method `go-logging.Logger` interface. |
| `container` | `github.com/jedi-knights/go-platform/container` | Stdlib-only generic DI container with context-propagated providers, sync.Once-backed singletons, child scopes, and LIFO close ordering. Available but not yet wired into services. |
| `logging` | `github.com/jedi-knights/go-logging/pkg/logging` | `slog`-based structured logging with trace ID and context support. Interface: `Debug`/`Info`/`Warn`/`Error` plus their `*Context` variants plus `With` plus `Enabled(ctx, slog.Level)`. Constructor is `logging.New(Config{...})`. |

### Phase 3 migration history (now complete)

- `libs/errors` → `github.com/jedi-knights/go-platform/apperrors`. Imports rewrote from `apperrors "github.com/ocrosby/identity-platform-go/libs/errors"` to plain `"github.com/jedi-knights/go-platform/apperrors"`.
- `libs/logging` → `github.com/jedi-knights/go-logging/pkg/logging`. `logging.NewLogger(Config{...})` calls became `logging.New(Config{...})`. The `Config` field set callers were using (`Level`, `Format`, `Output`, `ServiceName`, `Environment`) is preserved; `go-logging.Config` additionally exposes `StaticFields` and `Handler` for new call sites.
- `libs/jwtutil` → `github.com/jedi-knights/go-platform/jwtutil`. Pure import-path swap; `Claims`, `Sign`, `Parse`, `ParseWithAudience`, `ParseWithIssuer`, `NewClaims`, and the `Err*` sentinels are unchanged.
- `libs/httputil` → `github.com/jedi-knights/go-platform/httputil`. API equivalent; the underlying `Logger` is the broader `go-logging.Logger` and trace-ID generation delegates to `logging.NewTraceID()` with a panic-on-empty guard preserving the original CSPRNG-failure semantic.
- `libs/testutil` → `github.com/jedi-knights/go-platform/testutil`. The `noopLogger` implements the full 10-method `go-logging.Logger` interface (the four `*Context` methods discard the record; `Enabled` returns `false`).

---

## Versioning & Releases

Each service and library versions independently. Releases are triggered automatically on merge to `main` via Conventional Commits:

- `feat:` → minor bump
- `fix:`, `perf:`, `refactor:` → patch bump
- `feat!:` or `BREAKING CHANGE:` footer → major bump
- `chore:`, `docs:`, `style:`, `ci:`, `test:` → no release

Releases in the external `go-platform` and `go-logging` modules are independent of this repo. Service updates pull them in via `go get -u github.com/jedi-knights/go-platform` (or `go-logging`) followed by `go mod tidy` per affected service.

---

## Merging PRs — main must never go red

Because releases fire automatically on every merge to `main` (see above), a merge that lands with a failing check doesn't just look bad — it can trigger a broken release. **Never merge a PR whose CI checks are not actually green**, even when you're confident the failure will resolve itself once another pending PR merges (e.g., a dependent feature branch predates a bug-fix branch it needs).

The correct sequence when PR B depends on a fix landing in PR A:
1. Merge PR A.
2. Update PR B's branch against the new `main` (merge or rebase) so its CI re-runs against A's fix.
3. Wait for CI to actually go green on B.
4. Merge B.

Reasoning through "the code will be correct after both merge" is not a substitute for step 2–3 — a stale red check on a merged PR is a real process failure even if the resulting `main` happens to build and pass. This repo has no branch-protection rule blocking merges on failing checks, which makes this a discipline rule to hold yourself to, not something the platform will catch for you.
