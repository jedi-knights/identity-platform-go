# auth-server — Claude Context

## What This Service Does

The OAuth 2.0 authorization server. Issues, introspects, and revokes tokens. This is the hub of the identity platform — all other services depend on tokens it issues.

---

## Grant Type Status

| Grant Type | Status | Notes |
|-----------|--------|-------|
| `client_credentials` | Fully implemented | Includes refresh token issuance and RBAC claims |
| `refresh_token` | Fully implemented | Rotates refresh token on use (old deleted, new issued) |
| `authorization_code` | **Intentional stub** | `AuthorizationCodeStrategy.Handle` returns `ErrUnsupportedGrantType`; PKCE (RFC 7636) is the missing piece |

**Do not treat the `authorization_code` stub as forgotten work.** It is an extension point. Full implementation requires an ADR covering PKCE, redirect URI validation, and code issuance before any code is written.

---

## Adding a New Grant Type

1. Add a constant to `internal/domain/grant.go`
2. Implement `GrantStrategy` in `internal/application/grant_strategy.go`
3. Register it in `internal/container/container.go`

Nothing else changes — `GrantStrategyRegistry.Handle` dispatches via `Supports()` match.

---

## Token Endpoint Invariants

- **`Cache-Control: no-store`** must be set on all token responses (RFC 6749 §5.1).
- **Scope resolution**: intersect requested scopes with client's registered scopes — never grant more than the client is registered for. Unrecognised scopes return `ErrCodeForbidden`.
- **Secret comparison uses `subtle.ConstantTimeCompare`** (via `bcrypt.CompareHashAndPassword` in the `clientregistry` adapter). Do not replace with `==`.
- **Refresh token rotation**: on every `refresh_token` grant use, the old token is deleted and a new one is issued. This is enforced in `RefreshTokenStrategy.Handle`.

---

## Outbound Dependencies

| Port | Interface | Adapter | Env Var | Fallback |
|------|-----------|---------|---------|---------|
| Client authentication | `ports.ClientAuthenticator` | `adapters/outbound/clientregistry` | `AUTH_CLIENT_REGISTRY_URL` | In-memory client repo |
| User authentication | `ports.UserAuthenticator` | `adapters/outbound/identityservice` | `AUTH_IDENTITY_SERVICE_URL` | Nil (auth_code stub always errors) |
| RBAC permissions | `ports.SubjectPermissionsFetcher` | `adapters/outbound/policy` | `AUTH_POLICY_URL` | Nil (tokens issued without roles/permissions) |

When a URL env var is unset, `container.go` wires the fallback. This allows auth-server to run in isolation during development.

---

## Token Structure

Tokens are JWTs signed with HS256 using the key from `AUTH_SIGNING_KEY`. Claims type is `jwtutil.Claims` — the single source of truth in `libs/jwtutil`. The `Roles` and `Permissions` claims are populated at issuance from `SubjectPermissionsFetcher`; when the fetcher is nil, these fields are omitted (tokens remain valid for scope-only authorization).

Refresh tokens are opaque random hex values — never JWTs.

---

## RFC Notes

- **client_credentials refresh tokens**: RFC 6749 §4.4.3 says SHOULD NOT issue refresh tokens for this grant. This implementation does so intentionally to make the full token lifecycle testable. See `domain/token.go` for the rationale comment.
- **PKCE** (RFC 7636): `CodeVerifier` is parsed and stored in `GrantRequest` but validation is not yet implemented. Do not add validation without the full `authorization_code` flow.
