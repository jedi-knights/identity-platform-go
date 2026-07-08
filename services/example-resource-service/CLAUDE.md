# example-resource-service — Claude Context

## What This Service Does

Reference implementation of a resource server that consumes tokens issued by auth-server. Demonstrates RFC 6750 Bearer token usage, two-layer authorization (scope + policy), and the introspection-based revocation check.

---

## Two Authentication Middleware Options

Both are in `adapters/inbound/http/middleware.go`. Which one runs is wired in `container.go` based on env vars.

| Middleware | Env Var Required | Revocation Support |
|-----------|-----------------|-------------------|
| `IntrospectionAuthMiddleware` | `RESOURCE_INTROSPECTION_URL` | Yes — calls token-introspection-service on every request |
| `JWTAuthMiddleware` | None (fallback) | **No** — cannot detect revoked tokens until JWT expires |

**This is the most important thing to understand about this service.** If `RESOURCE_INTROSPECTION_URL` is not set, revoked tokens remain valid here until their expiry. For development without the full stack, this is acceptable. For any production-like deployment, always configure introspection.

---

## Two-Layer Authorization

Authorization is evaluated in sequence:

1. **Scope** (local, free): does this token have the required scope? Handled by `RequireScopeMiddleware`. Failure → `403 Forbidden` with `insufficient_scope`.
2. **Policy** (outbound, optional): is this specific subject permitted on this resource/action? Handled via `ports.PolicyChecker` → `authorization-policy-service`. When `RESOURCE_POLICY_URL` is unset, this layer is skipped and scope alone gates access.

Scope validates token capability ("can this token do reads?"); policy validates subject identity ("is this particular client/user allowed to read this resource?"). They serve different purposes — do not collapse them.

---

## Context Keys

After authentication middleware runs, the following are available in `r.Context()`:

| Key | Value |
|-----|-------|
| `contextKeySubject` | Subject claim from token |
| `contextKeyScopes` | `[]string` of scope values |
| `contextKeyClientID` | `client_id` claim |
| `contextKeyPermissions` | `[]string` of permissions (nil when absent — pre-RBAC tokens) |
| `contextKeyAcr` | Authentication-context-class-reference value (RFC 9470, ADR-0024 in auth-server), `""` when the introspector has none to offer |
| `contextKeyCNFJKT` | RFC 9449 DPoP confirmation thumbprint (RFC 9449, ADR-0025 in auth-server), `""` when the token is not DPoP-bound or the introspector has no `cnf.jkt` to offer |

Handlers must handle the case where `contextKeyPermissions` is nil — not all tokens carry RBAC claims.

---

## Step-Up Authentication (RFC 9470, ADR-0024)

`RequireACRMiddleware(requiredACR string)` gates a route on `contextKeyAcr` equaling `requiredACR`, demonstrated on `GET /resources/sensitive` (`RequireACRMiddleware("pwd")` layered under `RequireScopeMiddleware("read")`). Unlike `RequireScopeMiddleware`, both "absent from context" and "present but mismatched" collapse into the same `401 insufficient_user_authentication` challenge — RFC 9470 doesn't distinguish those two cases the way scope's authorization concept distinguishes 401 from 403.

**This mechanism has no live data source in the standard deployment today.** `IntrospectionAuthMiddleware` copies `result.Acr` into context unconditionally, but the documented default introspector — `token-introspection-service` — validates JWTs entirely locally and never calls auth-server, so it has no `acr` to offer regardless of configuration. `RequireACRMiddleware` is real, unit-tested code (`middleware_test.go`) that would light up automatically if a future `ports.TokenIntrospector` implementation sourced `Acr` (e.g., one that calls auth-server's own `/oauth/introspect` for this field). See auth-server's ADR-0024 for the full reasoning.

## Proof-of-Possession (RFC 9449, ADR-0025)

`RequireDPoPMiddleware` (in `dpop.go`) enforces DPoP whenever the token itself is bound — unlike `RequireScopeMiddleware`/`RequireACRMiddleware`, it takes no "requiredness" parameter; it reads `contextKeyCNFJKT` and is a no-op when empty (ordinary bearer token), or requires and validates a matching `DPoP` request header when non-empty. Demonstrated on `GET /resources/dpop-protected`.

**This mechanism has no live data source in the standard deployment today**, for the same reason `RequireACRMiddleware` doesn't (see ADR-0024): `token-introspection-service`, the documented default introspector, validates JWTs entirely locally and never calls auth-server, so it has no `cnf.jkt` to offer regardless of configuration. `RequireDPoPMiddleware` is real, unit-tested code that would light up automatically if a future `ports.TokenIntrospector` implementation sourced `CNFJKT`. Deliberately does **not** implement a `jti` replay cache at this layer — see the ADR's stated scope cut.

---

## RFC 6750 Compliance

- Missing or malformed `Authorization` header → `401` with `WWW-Authenticate: Bearer realm="..."`.
- Invalid/revoked token → `401` with `WWW-Authenticate: Bearer realm="...", error="invalid_token"`.
- Insufficient scope → `403` with `error="insufficient_scope"` (not `401` — the identity is known, just unauthorized).
- Introspection service error → `500` with `error="server_error"`.

---

## Outbound Dependencies

| Port | Env Var | Fallback |
|------|---------|---------|
| `ports.TokenIntrospector` | `RESOURCE_INTROSPECTION_URL` | `JWTAuthMiddleware` (local JWT validation) |
| `ports.PolicyChecker` | `RESOURCE_POLICY_URL` | Scope-only authorization |
