# ADR-0009: Authorization Code Grant with Mandatory PKCE

**Status**: Accepted
**Date**: 2026-06-23

## Context

The `authorization_code` grant is the only OAuth 2.0 flow that supports interactive end-user sign-in, and it is the flow MCP connectors and browser-delivered web apps need. Today it is an intentional stub:

- `AuthorizationCodeStrategy.Handle` in `services/auth-server/internal/application/grant_strategy.go` returns `ErrUnsupportedGrantType` ([line 410](../../services/auth-server/internal/application/grant_strategy.go#L410)).
- The HTTP handler `Handler.Authorize` in `services/auth-server/internal/adapters/inbound/http/handler.go` returns `501 Not Implemented` ([line 201](../../services/auth-server/internal/adapters/inbound/http/handler.go#L201)).
- `domain.GrantRequest` already carries `Code`, `CodeVerifier`, and `RedirectURI` fields that `parseGrantRequest` populates from the form body, but nothing consumes them.
- `domain.Client` already carries `RedirectURIs []string` with a `HasRedirectURI` exact-match method.

The pieces parsed but not yet wired must be connected, *and* the design must satisfy three constraints that the existing `client_credentials` flow does not:

1. **OAuth 2.1 §4.1.2.1 mandates PKCE.** OAuth 2.1 (draft-ietf-oauth-v2-1) folds RFC 7636 PKCE into the core authorization code flow as a hard requirement for *all* clients — public and confidential. The browser-app and MCP-connector use cases both fall in scope.
2. **OAuth 2.1 §4.1.2.2 mandates exact redirect URI matching** — no wildcards, no substring prefixes. The platform already enforces this at the data structure layer (`HasRedirectURI` is exact), but the policy needs to be ADR-anchored so it does not drift back to prefix matching for "convenience."
3. **RFC 6749 §10.5 / OAuth 2.1 §6.4.4 require single-use codes with replay detection** — re-use of an authorization code must invalidate all tokens already issued from that code. There is no code store today; this must be added.

The work fits behind the existing Strategy pattern (ADR-0003): the `AuthorizationCodeStrategy` body is the natural home for code validation and exchange. A separate concern — *who issues the code* and *how the user authenticates and consents* — belongs to the `/oauth/authorize` endpoint and is the subject of ADR-0011. **This ADR defines only the protocol mechanics and the storage/validation contracts.** ADR-0011 will wire in the login/consent UI.

## Decision

Complete the `authorization_code` grant with mandatory PKCE-S256, exact redirect URI matching, and a single-use code store. Introduce a new domain port `AuthorizationCodeIssuer` that ADR-0011's authorize-endpoint code will call once user identity and consent are established. Public clients are added as a first-class client type.

### Client types

`domain.Client` (auth-server) and the equivalent type in `client-registry-service` gain a `ClientType` field:

```go
type ClientType string

const (
    ClientTypeConfidential ClientType = "confidential" // has a client_secret
    ClientTypePublic       ClientType = "public"       // no secret; PKCE provides proof of possession
)
```

- **Confidential clients** authenticate with `client_secret` (existing behaviour). They use PKCE on top.
- **Public clients** have no `client_secret`. The PKCE `code_verifier` is the only proof that the redeemer is the same entity that initiated the flow. Token-endpoint authentication for public clients accepts `client_id` alone.

The existing `client_credentials` grant remains restricted to confidential clients (it has no PKCE channel); the existing seeded `test-client` keeps `ClientType: confidential`.

### PKCE — S256 only

Per RFC 7636 §4.2 and OAuth 2.1 §4.1.2.1: the `code_challenge_method` MUST be `S256`. The `plain` method is rejected outright (RFC 7636 §4.4.1 SHOULD-not, hardened to MUST-not here). The authorization code record stores the original challenge; the token-endpoint exchange recomputes `BASE64URL(SHA256(code_verifier))` and compares with `subtle.ConstantTimeCompare`.

- **`code_challenge`**: 43–128 characters, base64url charset (RFC 7636 §4.2). Validated at the authorize endpoint (ADR-0011 owns the parse; this ADR specifies the validation).
- **`code_verifier`**: 43–128 characters, `[A-Z a-z 0-9 \-._~]` only (RFC 7636 §4.1). Validated at the token endpoint.
- The comparison must use constant-time bytes equality. Vary-length inputs are length-checked first, then padded to a fixed buffer before comparison.

### Authorization code shape

A new domain type and repository:

```go
type AuthorizationCode struct {
    Code                string    // opaque random hex, 32 bytes (256 bits of entropy)
    ClientID            string
    Subject             string    // user id from identity-service
    RedirectURI         string    // exact URI presented at /authorize
    Scopes              []string  // resolved at /authorize
    CodeChallenge       string
    CodeChallengeMethod string    // always "S256" — stored for forward-compat
    Nonce               string    // OIDC §3.1.2.5 — empty when openid scope absent (ADR-0010 reads it)
    IssuedAt            time.Time
    ExpiresAt           time.Time // IssuedAt + 60s (RFC 6749 §4.1.2 recommends ≤ 10 min; OAuth 2.1 §4.1.3 suggests ≤ 60s)
}

type AuthorizationCodeRepository interface {
    Save(ctx context.Context, code *AuthorizationCode) error
    // Consume atomically reads and deletes the code by its raw value.
    // Returns ErrAuthorizationCodeNotFound for unknown/expired/already-consumed codes.
    Consume(ctx context.Context, raw string) (*AuthorizationCode, error)
    // FindByCode is read-only; used only by the replay-detection path. The Consume
    // path is the normal lookup and must be used by the token endpoint.
    FindByCode(ctx context.Context, raw string) (*AuthorizationCode, error)
}
```

**TTL is 60 seconds.** OAuth 2.1 §4.1.3 suggests "short, e.g., 60 seconds." The legitimate window from redirect to token-endpoint POST is dominated by network latency and the user-agent redirect chain — sub-second in practice. 60s leaves comfortable headroom for slow clients and forbids exfiltration-then-exchange flows that take longer.

**Two adapters mirroring ADR-0006**:

| Adapter | Storage | When used |
|---|---|---|
| `memory.AuthorizationCodeRepository` | in-process map with TTL eviction | local dev fallback when `AUTH_REDIS_URL` unset |
| `redis.AuthorizationCodeRepository` | Redis key `authcode:<raw>` with `SETEX` TTL = ExpiresAt - now | production; same Redis instance as token store |

The Redis adapter's `Consume` operation uses a single Lua script for `GET` + `DEL` atomicity — replay detection depends on the read-and-delete being a single round-trip. A two-call `GET` followed by `DEL` admits a race where two concurrent token-endpoint requests for the same code both see the value.

### Replay detection

If `Consume` returns `ErrAuthorizationCodeNotFound` *and* a non-trivial token issuance has already happened for that code, the code has been replayed (or was bogus). Two cases:

| Case | Detection | Response |
|---|---|---|
| First-time use, valid code | `Consume` returns the code; the token-endpoint flow proceeds | `200 OK` with tokens |
| Replay | `Consume` returns `ErrAuthorizationCodeNotFound`; but the access/refresh tokens *correlated* to that code are still in their stores | Revoke every access and refresh token whose `code_jti` claim matches the code, log a security event, return `invalid_grant` |
| Bogus / expired | `Consume` returns `ErrAuthorizationCodeNotFound`; no correlated tokens exist | Return `invalid_grant` |

To make replay detection possible, the access and refresh tokens issued from an authorization code embed a new `code_jti` claim equal to the authorization code's raw value (or a HMAC of it, to avoid storing the raw code itself in JWTs). The token revocation path gains an `RevokeByCodeJTI(ctx, codeJTI string) error` method that deletes all access and refresh tokens carrying that claim. This is a small extension to the existing `TokenRepository` and `RefreshTokenRepository` interfaces:

```go
type TokenRepository interface {
    // ...existing methods...
    DeleteByCodeJTI(ctx context.Context, codeJTI string) error
}
```

The memory adapters do a linear scan; the Redis adapter maintains a secondary index `authcode-tokens:<code_jti>` (a set of token JTIs) populated on issuance and read on revoke.

### Token-endpoint exchange — validation order

The `AuthorizationCodeStrategy.Handle` body performs these checks in order. Any failure returns the listed OAuth error code (RFC 6749 §5.2) with HTTP 400, except `invalid_client` which is 401:

| # | Check | Failure → error code |
|---|---|---|
| 1 | `grant_type == authorization_code` (dispatched by registry, asserted here) | `unsupported_grant_type` |
| 2 | `code` present in request | `invalid_request` |
| 3 | `redirect_uri` present in request | `invalid_request` |
| 4 | `code_verifier` present in request | `invalid_request` (PKCE mandatory) |
| 5 | Client authenticated — confidential: secret matches; public: `client_id` exists | `invalid_client` |
| 6 | Client `HasGrantType(authorization_code)` | `unauthorized_client` |
| 7 | `repo.Consume(code)` succeeds — atomic read-and-delete | `invalid_grant` (also triggers replay-detection path) |
| 8 | `code.ClientID == request.ClientID` | `invalid_grant` |
| 9 | `code.RedirectURI == request.RedirectURI` (byte-exact) | `invalid_grant` |
| 10 | `time.Now().Before(code.ExpiresAt)` | `invalid_grant` |
| 11 | `code.CodeChallengeMethod == "S256"` | `invalid_grant` (defensive — Save only accepts S256) |
| 12 | `S256(verifier) == code.CodeChallenge` (constant-time) | `invalid_grant` |

Only after all 12 checks pass: issue access token, optional ID token (ADR-0010 wires `openid` scope), refresh token (per ADR-0014 rotation rules). Both tokens carry the `code_jti` claim.

### Authorize-endpoint contract (consumed by ADR-0011)

This ADR does not implement `GET /oauth/authorize`. It defines the contract the future implementation must satisfy by introducing a port:

```go
type AuthorizationCodeIssuer interface {
    Issue(ctx context.Context, req IssueCodeRequest) (string, error)
}

type IssueCodeRequest struct {
    ClientID            string
    Subject             string   // user id from identity-service (post-login)
    RedirectURI         string   // already validated against client.RedirectURIs
    Scopes              []string // already intersected with client.Scopes
    CodeChallenge       string
    CodeChallengeMethod string   // must be "S256"
    Nonce               string   // OIDC nonce; empty when not requested
}
```

The implementation lives in `application/authcode_issuer.go` and satisfies the port declared in `ports/inbound.go` (`ports.AuthorizationCodeIssuer`): validates `CodeChallengeMethod == "S256"`, generates 32 bytes of CSPRNG entropy (`crypto/rand`), hex-encodes, stores via `AuthorizationCodeRepository.Save`, returns the raw code. ADR-0011's HTTP handler builds the redirect URL with `?code=<raw>&state=<state>`.

### Redirect URI matching policy

Stated explicitly so it does not drift: the redirect URI presented at the token endpoint must be **byte-exact** equal to the URI used at the authorize endpoint, which itself must be **byte-exact** present in the client's registered `RedirectURIs` list. No normalization, no case folding, no trailing-slash tolerance, no query string stripping. The existing `Client.HasRedirectURI` is correct; this ADR forbids relaxing it.

### Compile-time interface checks

```go
var _ domain.AuthorizationCodeRepository = (*AuthorizationCodeRepository)(nil)
var _ ports.AuthorizationCodeIssuer = (*authCodeIssuer)(nil)
```

### Configuration surface

| Service | New env var | Default | Purpose |
|---|---|---|---|
| `auth-server` | `AUTH_AUTHORIZATION_CODE_TTL` | `60s` | Authorization code lifetime |
| `auth-server` | (none new) | — | Code store reuses `AUTH_REDIS_URL` from ADR-0006 with fallback to memory |

## Consequences

**Positive**

- The platform supports browser-delivered web apps and MCP connectors via the standard OAuth 2.1 authorization code + PKCE flow — no custom client-side cryptography required.
- Public clients are first-class: a connector running in a browser tab or a native app does not need a `client_secret` (which it could not protect anyway).
- Replay detection lets a compromised authorization code be neutralised retroactively — once it has been used twice, every token issued from it is revoked in milliseconds.
- The 60-second code TTL bounds the time-of-check-to-time-of-use window. An attacker who exfiltrates a code from a victim's browser history has at most 60 seconds (typically a few seconds) before it is invalidated by the legitimate exchange.
- The `AuthorizationCodeIssuer` port is the clean seam ADR-0011 needs — UI rendering and form handling can be designed without touching token logic.

**Negative / Trade-offs**

- The token endpoint now performs more I/O per call: code lookup, code delete, and (on replay) a token-revocation sweep. At nominal request rates the cost is negligible; under attack (mass replay attempts) the `RevokeByCodeJTI` linear scan against the in-memory token repo could be hot. Mitigation: the Redis-backed token repo uses the secondary index — for any production deployment using Redis, the sweep is O(1) lookup of a set.
- Mandating S256 means a hypothetical low-entropy embedded device cannot use the `plain` PKCE method. This is a deliberate exclusion — the cost of allowing `plain` is that downgrade attacks become possible, and the reference implementation does not target devices without SHA-256.
- Adding `ClientType` to the client model is a backwards-compatible migration (zero-value `""` treated as confidential), but it requires a `client-registry-service` schema change once that service moves to PostgreSQL (ADR-0007). Migration: `ALTER TABLE clients ADD COLUMN client_type TEXT NOT NULL DEFAULT 'confidential'`.
- The `code_jti` claim is non-standard. It is internal to the platform — resource servers do not need to read it. The cost is a small per-token byte overhead; the benefit is making replay revocation trivial.

## Alternatives Considered

- **Allow PKCE-plain for backwards compatibility.** Rejected. `plain` adds no security over a leaked code and admits a downgrade attack on a confidential client whose server-side state was compromised. OAuth 2.1 already forbids it for public clients; this ADR extends the prohibition to confidential clients for consistency. The cost is zero — there is no legacy code base on this platform.
- **Use a stateless authorization code (HMAC-signed claims) instead of a code store.** Removes the round-trip to the code store at exchange time. Rejected because single-use enforcement requires a store anyway — a stateless code can be replayed indefinitely within its TTL unless the platform tracks "already used" codes, which is the store. Two stores (one for issuance, one for consumption tracking) is worse than one for both.
- **Bind the code to a session cookie or device fingerprint instead of PKCE.** Solves the same threat (code interception) but couples auth to a transport that varies across MCP / web / native. PKCE is the standard answer; deviating would block the MCP and OIDC ecosystem from interoperating with this platform.
- **Use `state` parameter to defend against CSRF only, not as part of the code binding.** Kept — `state` is the client's responsibility, not the server's. The authorization code itself binds via `code_challenge` + `redirect_uri` + `client_id`. `state` round-trips unchanged through the authorize and redirect.
- **Make `code_jti` a HMAC of the raw code (no plaintext in the JWT).** Considered as a privacy improvement. Rejected as overkill for this ADR — the raw code is destroyed at first exchange; even the HMAC adds machinery without a concrete threat model. Easy to add later by changing the `code_jti` claim's derivation in one place.
