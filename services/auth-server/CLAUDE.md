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
| `urn:ietf:params:oauth:grant-type:device_code` | Fully implemented (ADR-0022) | RFC 8628 device flow; polling maps to `authorization_pending`/`access_denied`/`expired_token` via `*application.DevicePollError`; no `slow_down` enforcement (stated ADR limitation) |

The authorization_code grant runs a 12-step validation pipeline at the token endpoint (see ADR-0009 §"Token-endpoint exchange — validation order"). Both public clients (no secret, PKCE-only) and confidential clients (secret + PKCE) work; the `domain.Client.Type` field controls which path the strategy follows.

---

## ADR-0022 endpoints — `/device_authorization` and `/internal/device/decision`

`POST /device_authorization` (client-credential authed, public-client-tolerant — same non-secret-enforcement carve-out as the device_code grant itself) mints a `device_code` (256-bit CSPRNG, hex) and a `user_code` (32-symbol Crockford Base32 alphabet, excludes I/L/O/U, formatted `XXXX-XXXX`), persists a `domain.DeviceAuthorization` (memory or Redis, mirroring the auth-code adapter's two-key lookup problem — see ADR-0022), and returns `{device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval}`.

`POST /internal/device/decision` is bearer-authenticated with the same `AUTH_LOGIN_UI_SERVICE_TOKEN` `/internal/issue-code` uses. `login-ui`'s `/device` verification page calls it after the user signs in and clicks Approve or Deny. `Approve`/`Deny` are keyed by `user_code`; a subsequent poll at `/oauth/token` resolves by `device_code` and `Consume`s the record exactly once.

Both endpoints stay disabled until `AUTH_LOGIN_UI_URL` is set: `/device_authorization` is nil-resolved (404) and `/internal/device/decision` returns 404 when the operator has not configured `AUTH_LOGIN_UI_SERVICE_TOKEN`, mirroring ADR-0011's `/oauth/authorize` / `/internal/issue-code` degradation.

---

## ADR-0011 endpoints — `/oauth/authorize` and `/internal/issue-code`

`/oauth/authorize` (GET) validates the request, persists a `LoginChallenge` (memory or Redis, mirroring the auth-code adapter), and 302-redirects to `<AUTH_LOGIN_UI_URL>/sign-in?login_challenge=<id>`. Validation enforces: `response_type=code`, PKCE-S256 mandatory, redirect_uri exact-match against the client's registered list, requested-scope subset of the client's registered scopes. Error routing follows RFC 6749 §3.1.2.4 / §4.1.2.1 — bad `client_id` or `redirect_uri` render the error (do not redirect to an attacker URI); all other parameter errors 302 back to the validated `redirect_uri` with `?error=&state=`.

`/internal/issue-code` (POST) is bearer-authenticated with `AUTH_LOGIN_UI_SERVICE_TOKEN` (constant-time compare). `login-ui` calls it after a successful sign-in. The handler atomically `Consume`s the challenge — replay is impossible — validates the granted-scope set is a subset of the request scopes, and calls `ports.AuthorizationCodeIssuer.Issue` with an `IssueCodeRequest` populated from the stored challenge (including its `Nonce`). Returns `{code, redirect_uri, state}` — `login-ui` 302s the user-agent to `<redirect_uri>?code=&state=`.

Both endpoints stay disabled until the matching env vars are set: `/oauth/authorize` returns 501 when `AUTH_LOGIN_UI_URL` is empty, and `/internal/issue-code` returns 404 when `AUTH_LOGIN_UI_SERVICE_TOKEN` is empty. This lets deployments without `login-ui` keep the original stub behavior.

---

## ADR-0023 — JWT-Bearer Client Authentication (RFC 7521/7523)

`client_credentials`, `refresh_token`, and `authorization_code` accept a `client_assertion` + `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` form pair as an alternative to `client_secret`. `client_id` is still required and is cross-checked against the assertion's `iss`/`sub` claims after signature verification — it is never derived solely from the assertion (see the ADR's "Alternatives Considered").

A client opts in by registering a `jwks_uri` with client-registry-service (`POST /clients` or `POST /register`, `jwks_uri` field). A client with no `jwks_uri` cannot use this path — `application.ClientAssertionValidator.Authenticate` rejects it before ever attempting to verify a signature.

Verification is RS256-only (RFC 8725 §3.1 algorithm-confusion defence, same stance as ADR-0008) and enforces RFC 7523 §3's claim set: `iss`/`sub` == `client_id`, `aud` contains `AUTH_JWT_ISSUER`, `exp` present and unexpired, `jti` present and not previously seen (`domain.ClientAssertionReplayRepository`, memory or Redis via `AUTH_REDIS_URL` — same dispatch as every other repository in this service).

`application.ClientAssertionValidator` is **not** an adapter — it lives in `internal/application` alongside the grant strategies, depending only on `ports.ClientLookup` and `ports.ClientJWKSFetcher`. This is deliberate: `jwtutil.ParseRS256` cannot be reused here because it hard-enforces the platform's own RFC 9068 `at+jwt` JOSE header, which a third-party client assertion never carries.

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
| Client-assertion JWKS resolution | `ports.ClientJWKSFetcher` | `adapters/outbound/jwks` (ADR-0023) | — always wired | Per-client-URI cache; no env var — every client's `jwks_uri` is fetched on demand |

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
