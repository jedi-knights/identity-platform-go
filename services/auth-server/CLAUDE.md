# auth-server — Claude Context

## What This Service Does

The OAuth 2.0 authorization server. Issues, introspects, and revokes tokens. This is the hub of the identity platform — all other services depend on tokens it issues.

---

## Grant Type Status

| Grant Type | Status | Notes |
|-----------|--------|-------|
| `client_credentials` | Fully implemented | Includes refresh token issuance and RBAC claims |
| `refresh_token` | Fully implemented | Rotates refresh token on use (old deleted, new issued) |
| `authorization_code` | Fully implemented (ADR-0009) | Mandatory PKCE-S256 for every client; exact redirect-URI match; 60s default code TTL; atomic Consume detects replay |

The authorization_code grant runs a 12-step validation pipeline at the token endpoint (see ADR-0009 §"Token-endpoint exchange — validation order"). Both public clients (no secret, PKCE-only) and confidential clients (secret + PKCE) work; the `domain.Client.Type` field controls which path the strategy follows.

---

## ADR-0011 endpoints — `/oauth/authorize` and `/internal/issue-code`

`/oauth/authorize` (GET) validates the request, persists a `LoginChallenge` (memory or Redis, mirroring the auth-code adapter), and 302-redirects to `<AUTH_LOGIN_UI_URL>/sign-in?login_challenge=<id>`. Validation enforces: `response_type=code`, PKCE-S256 mandatory, redirect_uri exact-match against the client's registered list, requested-scope subset of the client's registered scopes. Error routing follows RFC 6749 §3.1.2.4 / §4.1.2.1 — bad `client_id` or `redirect_uri` render the error (do not redirect to an attacker URI); all other parameter errors 302 back to the validated `redirect_uri` with `?error=&state=`.

`/internal/issue-code` (POST) is bearer-authenticated with `AUTH_LOGIN_UI_SERVICE_TOKEN` (constant-time compare). `login-ui` calls it after a successful sign-in. The handler atomically `Consume`s the challenge — replay is impossible — validates the granted-scope set is a subset of the request scopes, and calls `ports.AuthorizationCodeIssuer.Issue` with an `IssueCodeRequest` populated from the stored challenge (including its `Nonce`). Returns `{code, redirect_uri, state}` — `login-ui` 302s the user-agent to `<redirect_uri>?code=&state=`.

Both endpoints stay disabled until the matching env vars are set: `/oauth/authorize` returns 501 when `AUTH_LOGIN_UI_URL` is empty, and `/internal/issue-code` returns 404 when `AUTH_LOGIN_UI_SERVICE_TOKEN` is empty. This lets deployments without `login-ui` keep the original stub behavior.

---

## Adding a New Grant Type

1. Add a constant to `internal/domain/grant.go`
2. Implement `GrantStrategy` in `internal/application/grant_strategy.go`
3. Register it in `internal/container/container.go`

Nothing else changes — `GrantStrategyRegistry.Handle` dispatches via `Supports()` match.

---

## Token Endpoint Invariants

- **`Cache-Control: no-store`** must be set on all token responses (RFC 6749 §5.1).
- **Scope resolution**: intersect requested scopes with client's registered scopes — never grant more than the client is registered for. Unrecognized scopes return `ErrCodeForbidden`.
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

Per ADR-0008, tokens are JWTs signed with **RS256 by default**. The current signing key is held in a `domain.KeySet` built from `AUTH_JWT_RSA_PRIVATE_KEY_PEM` (production) or generated in-memory at startup (local dev fallback). Every token carries a `kid` JOSE header so verifiers can resolve the public key via `GET /.well-known/jwks.json`.

Set `AUTH_JWT_SIGNING_ALG=HS256` and `AUTH_JWT_SIGNING_KEY` to fall back to the legacy shared-HMAC path during migration. Under HS256 the JWKS endpoint is **not** registered — a probe for `/.well-known/jwks.json` returns 404.

Claims type is `jwtutil.Claims` — the single source of truth in `go-platform/jwtutil`. The `Roles` and `Permissions` claims are populated at issuance from `SubjectPermissionsFetcher`; when the fetcher is nil, these fields are omitted (tokens remain valid for scope-only authorization).

Refresh tokens are opaque random hex values — never JWTs.

### Key rotation surface

| Env var | Slot | When emitted in JWKS |
|---|---|---|
| `AUTH_JWT_RSA_PRIVATE_KEY_PEM` | Current — used to sign new tokens | Always |
| `AUTH_JWT_RSA_PRIVATE_KEY_PEM_PREVIOUS` | Retiring — kept for verifier-side validity during the rotation window | When set |
| `AUTH_JWT_RSA_PRIVATE_KEY_PEM_NEXT` | Pre-staged successor — visible to verifiers ahead of promotion to Current | When set |

Rotation is the operator pattern: stage `_NEXT` → restart → promote `_NEXT` to current and previous-current to `_PREVIOUS` → restart → drop `_PREVIOUS` after access-token TTL has fully drained.

---

## RFC Notes

- **client_credentials refresh tokens**: RFC 6749 §4.4.3 says SHOULD NOT issue refresh tokens for this grant. This implementation does so intentionally to make the full token lifecycle testable. See `domain/token.go` for the rationale comment.
- **PKCE** (RFC 7636 + OAuth 2.1 §4.1.2.1): mandatory and S256-only. `plain` is rejected at the issuer (ADR-0009). The S256 comparison at the token endpoint uses `subtle.ConstantTimeCompare`. Do not relax to per-client opt-in — public clients have nothing else to authenticate with.
- **RS256 + JWKS** (RFC 7517 / RFC 7518): per ADR-0008, the algorithm-confusion defence (RFC 8725 §3.1) is enforced by `jwtutil.ParseRS256` — HS256-signed tokens are rejected outright. Do not relax that check.
