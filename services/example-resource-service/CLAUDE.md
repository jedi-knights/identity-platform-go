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

Handlers must handle the case where `contextKeyPermissions` is nil — not all tokens carry RBAC claims.

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
