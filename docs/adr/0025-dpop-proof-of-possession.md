# ADR-0025: DPoP — Demonstrating Proof of Possession (RFC 9449)

**Status**: Accepted
**Date**: 2026-07-08

## Context

Every access token this platform issues today is a bearer token: whoever holds the raw string can use it. If a token leaks — logged, cached, sniffed off an untrusted channel — the thief can replay it from anywhere until it expires. RFC 9449 (DPoP) fixes this by binding a token to a key pair the client generates and never discloses: every request to the token endpoint (to *get* a token) and every request to a resource server (to *use* one) must be accompanied by a `DPoP` header — a short-lived JWT, signed by the client's private key, that proves the client currently holds that key. The resource server checks the presented proof's public key against a thumbprint embedded in the token; a stolen token without the matching private key is useless.

Two pieces of prior art this ADR builds on directly:

- **`domain.IntrospectResponse`** (`services/auth-server/internal/domain/token.go`) is this repo's precedent for carrying protocol metadata that doesn't fit on the signed JWT itself — RAR (ADR-0017) added `authorization_details` here, step-up auth (ADR-0024) added `acr`. DPoP's `cnf.jkt` (RFC 7662 §2.2 / RFC 9449 §6.1) follows the same shape.
- **`domain.AuthorizationCodeRepository.Consume`** (`services/auth-server/internal/domain/authorization_code.go`) is this repo's only existing single-use-token repository, but it's the wrong shape for DPoP: it's "read-and-delete" (the code is consumed exactly once and nothing about it is remembered afterward). DPoP's `jti` replay cache needs "insert-if-absent, TTL'd" — reject a proof only if its `jti` was *already seen* within the freshness window, otherwise remember it until the window closes. This is a new repository shape for this codebase.

A harder constraint, confirmed by research before writing any code: **`go-platform/jwtutil` cannot verify a DPoP proof at all.** Its `ParseRS256` hard-codes `typ:"at+jwt"` (RFC 9068) and resolves keys only by `kid` via a caller-supplied `KeySource` returning `*rsa.PublicKey`. A DPoP proof carries its public key inline in the JWT header (`jwk`, RFC 7517 §4.5), has `typ:"dpop+jwt"`, and is commonly ES256 (P-256), not RS256. None of that fits `jwtutil`'s shape, and `jwtutil` is an externally-versioned module this repo doesn't own — the same constraint ADR-0024 hit for `acr`. Nothing in this repo or its dependencies (confirmed: no `jose`/`jwx`/`go-jose` package anywhere in any `go.sum`) can decode a JWK back into a `crypto.PublicKey`, and RFC 7638 thumbprinting doesn't exist anywhere either. Both are new code, written here rather than upstreamed, following the same "don't touch the external module" precedent ADR-0024 established for `acr`. `github.com/golang-jwt/jwt/v5` — already a **direct** dependency of both `auth-server` and `example-resource-service` — is used directly for parsing/verifying the DPoP proof JWT itself, since `jwtutil` doesn't cover this shape.

## Decision

Implement DPoP as **optional, per-request**: a client that never sends a `DPoP` header gets today's unchanged Bearer-token behavior. A client that sends one gets a `DPoP`-typed, key-bound token. This mirrors how PKCE (ADR-0009) is mandatory but DPoP is not — RFC 9449 explicitly leaves requiring DPoP up to deployment policy, and this reference implementation doesn't have a scenario (like PKCE's public-client-has-nothing-else problem) that forces mandatory adoption.

### New primitives (domain layer, stdlib-only — no jwtutil, no golang-jwt)

- `domain.JWK` — decode-only struct for the subset of RFC 7517/7518 members DPoP needs (`kty`, `crv`, `x`, `y` for EC; `kty`, `n`, `e` for RSA). `PublicKey()` builds a `*ecdsa.PublicKey` or `*rsa.PublicKey`. `Thumbprint()` implements RFC 7638 §3.2 exactly: canonical JSON of only the required members in lexicographic key order (`{"crv":...,"kty":"EC","x":...,"y":...}` for EC; `{"e":...,"kty":"RSA","n":...}` for RSA), SHA-256, unpadded base64url. This is the mirror image of `jwks.go`'s existing `encodeJWK` (`SigningKey → jwk`, write-only, RSA-only) — `domain.JWK` goes the other direction (`jwk → PublicKey`) and adds EC support, since DPoP proofs are typically ES256.
- `domain.TokenTypeDPoP = "DPoP"` — a third `TokenType` constant alongside `TokenTypeBearer`/`TokenTypeOpaque`. RFC 9449 §5 requires the token endpoint to return `"token_type":"DPoP"` (not `"Bearer"`) when a proof was validated.
- `domain.Token.JKT string` — the RFC 7638 thumbprint of the client's public key, empty for ordinary bearer tokens.
- `domain.IntrospectResponse.CNF *domain.Confirmation` where `Confirmation{JKT string 'json:"jkt"'}` — surfaces `"cnf":{"jkt":"..."}` on `/oauth/introspect` per RFC 9449 §6.1, omitted entirely for non-DPoP tokens.
- `domain.DPoPProofRepository` — `MarkUsed(ctx, jti string, expiresAt time.Time) error`, returning `domain.ErrDPoPProofReplayed` if `jti` was already marked and hasn't expired. "Insert-if-absent, TTL'd" — the new repository shape described above. Memory adapter: one mutex + map, lazily evicting expired entries on access (bounded by the freshness window, never grows unboundedly). Redis adapter: `SET NX EX`, one round trip, no Lua script needed (unlike `AuthorizationCode.Consume`, which needs get+delete atomicity `SET NX` doesn't provide).

### DPoP proof validation (application layer — this is where golang-jwt/jwt/v5 is used directly)

`application.DPoPValidator.Validate(ctx, proofJWT, htm, htu string) (jkt string, err error)`:

1. Parse the JWT header only far enough to read `typ` and `jwk` — reject if `typ != "dpop+jwt"` or `jwk` is absent (a `kid`-only header, or an `x5c` header, is not what RFC 9449 requires).
2. Decode `jwk` via `domain.JWK.PublicKey()`, verify the JWT signature against it using `jwt.ParseWithClaims` restricted to `{ES256, RS256}` (`jwt.WithValidMethods`) — an algorithm mismatch between the header's declared `alg` and the actual key type fails at this step.
3. Validate claims: `htm` must equal the HTTP method of the request being proved (`POST` at the token endpoint); `htu` must equal the request's URL with query and fragment stripped (RFC 9449 §4.3) — reconstructed directly from the live `*http.Request` at the HTTP layer, not from any configured "public base URL," so this works correctly regardless of whether `AUTH_METADATA_PUBLIC_BASE_URL` is set; `iat` must be within a 5-minute freshness window of now (a hardcoded constant, matching this codebase's existing style of hardcoded TTLs — 60s auth-code TTL, 5m token-exchange TTL — rather than a new env var for something this narrow); `jti` must be non-empty.
4. `domain.JWK.Thumbprint()` on the same key that verified the signature → `jkt`.
5. `DPoPProofRepository.MarkUsed(ctx, jti, iat+freshnessWindow)` — replay within the window is rejected.

### Where this plugs into the existing pipeline

DPoP is **grant-agnostic** (RFC 9449 §5 applies uniformly regardless of which grant is being used), so validation happens once in `Handler.Token`, between `parseGrantRequest` and `issuer.IssueToken` — the same place body-size capping and form-parsing already happen, before any grant-specific strategy runs. A present-but-invalid `DPoP` header fails the whole request with `invalid_dpop_proof` (400) per RFC 9449 §5; an absent header falls through to today's unchanged Bearer path. The resulting `jkt` is carried on `domain.GrantRequest.DPoPJKT` into the strategy exactly the same way `AuthorizationDetails` already crosses that boundary.

**Scope cut, stated explicitly**: only `client_credentials`, `refresh_token`, and `authorization_code` — this platform's three fully-implemented grants — bind DPoP. `token_exchange` is excluded, mirroring ADR-0023's precedent of excluding `token_exchange`/`device_code` from a cross-cutting client-auth upgrade for the same reason (lower call volume, already has its own semantics to reason about, not worth the added combinatorial surface here).

### Resource-server enforcement (`example-resource-service`)

`ports.IntrospectionResult.CNFJKT string` (empty for non-DPoP tokens) is populated by `introspection.Client` from the introspection response's `cnf.jkt`, mirroring exactly how `Acr` was threaded through in ADR-0024. A new `RequireDPoPMiddleware` — layered like `RequireACRMiddleware`, reading the incoming request's own `DPoP` header and comparing its thumbprint against `contextKeyDPoPJKT` — rejects with `401` and `WWW-Authenticate: error="invalid_token"` (RFC 9449 §7.1) whenever a token is DPoP-bound but the presented proof's key doesn't match, or no proof was presented at all. A token with no `cnf.jkt` (ordinary bearer) is unaffected — the middleware is opt-in per route, same as `RequireScopeMiddleware`/`RequireACRMiddleware`.

`example-resource-service` validates the proof's `htm`/`htu`/`iat` the same way `DPoPValidator` does on the AS side (small, deliberate duplication of the JWT-parsing logic — "a little copying is better than a little dependency" — rather than a shared internal package, since these are two separate Go modules in this workspace with no existing shared-code mechanism beyond the external `go-platform` module this ADR already can't extend). **Scope cut, stated explicitly**: no `jti` replay cache at the resource-server layer. RFC 9449 §11.1's replay concern matters most at token issuance (a stolen `DPoP` proof used to mint a *new* token is the higher-value attack); a resource-server-side replay cache is a defense-in-depth addition RFC 9449 §7.1 phrases as "SHOULD," not "MUST," and adding a second per-service replay-cache adapter (plus wiring a Redis-or-memory choice into a service that has no Redis dependency today) roughly doubles this phase's surface for a secondary protection. Deferred to a future ADR if this reference platform ever needs to demonstrate it.

### Metadata

`dpop_signing_alg_values_supported: ["ES256", "RS256"]` advertised unconditionally in both `OAuthMetadata()` and `OIDCMetadata()` (DPoP is an OAuth-layer capability, not OIDC-specific) — mirrors `AuthorizationDetailsTypesSupported`'s existing pattern of an unconditionally-advertised capability list.

## Consequences

### Positive

- Fully real, fully unit- and acceptance-tested for the AS-side round trip (proof at `/oauth/token` → `DPoP`-typed token → `cnf.jkt` on introspection) without touching any external dependency this repo doesn't own.
- New JWK-decode/thumbprint code and the new replay-repository shape are both stdlib-only or reuse the existing memory/Redis adapter convention (ADR-0005) — no new third-party dependency.
- Backward compatible by construction: no `DPoP` header, no behavior change.

### Negative

- No resource-server-side `jti` replay protection (stated scope cut above) — a captured-in-flight DPoP proof could in principle be replayed against the resource server within its freshness window (not against the token endpoint, where the AS-side replay cache does apply). Narrow window (5 minutes), and still requires possession of a validly-signed proof, which requires the private key — the core proof-of-possession guarantee (a bare stolen access token is useless without it) holds regardless.
- `token_exchange` tokens are never DPoP-bound (stated scope cut above).
- The 5-minute freshness window and the ES256/RS256 algorithm allow-list are hardcoded, not configurable — consistent with this codebase's existing style for narrowly-scoped constants, but a production deployment wanting a stricter window has no config knob without a code change.

## Alternatives Considered

- **Add `cnf`/`jkt` support to `go-platform/jwtutil`.** Rejected — out of reach from this repo (separate module, separate release cycle), same reasoning ADR-0024 already applied to `acr`.
- **Require DPoP unconditionally, like PKCE.** Rejected — PKCE is mandatory because public clients have no other way to bind an authorization code to themselves (ADR-0009's stated reasoning). DPoP doesn't have an equivalent forcing function here; making it mandatory would break every existing acceptance scenario and client integration for a reference implementation that has no threat model requiring it.
- **Thread DPoP validation through each `GrantStrategy` individually (constructor parameter, like `permsFetcher`).** Rejected — DPoP is grant-agnostic per RFC 9449 §5; validating once at the handler level before dispatch (mirroring how rate-limiting and body-size capping already work) avoids touching three strategy constructors and their `container.go` call sites for a check that's identical regardless of grant type.
- **Add a resource-server-side `jti` replay cache now.** Rejected for this phase — RFC 9449 marks it "SHOULD" not "MUST," and it would add a second per-service replay-cache adapter (plus a Redis-or-memory wiring decision for a service with no existing Redis dependency) for a secondary protection layer. Deferred; revisit if a future ADR needs to demonstrate defense-in-depth at the resource-server layer specifically.
- **Support `token_exchange` DPoP binding too.** Rejected for this phase, mirroring ADR-0023's precedent — lower call volume, separate semantics, not worth the combinatorial surface increase here.

## References

- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 7638 — JSON Web Key (JWK) Thumbprint](https://datatracker.ietf.org/doc/html/rfc7638)
- [RFC 7517 — JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 7518 §6 — JSON Web Algorithms, Cryptographic Algorithms for Keys](https://datatracker.ietf.org/doc/html/rfc7518#section-6)
- [RFC 7662 §2.2 — Token Introspection Response](https://datatracker.ietf.org/doc/html/rfc7662#section-2.2)
- [ADR-0005 — Adapter Scalability Contract](0005-adapter-scalability-contract.md)
- [ADR-0008 — RS256/JWKS Token Signing](0008-rs256-jwks-token-signing.md)
- [ADR-0009 — Authorization Code + PKCE](0009-authorization-code-pkce.md)
- [ADR-0017 — Rich Authorization Requests (RFC 9396)](0017-rich-authorization-requests-rfc-9396.md)
- [ADR-0024 — Step-Up Authentication Challenge (RFC 9470)](0024-step-up-authentication-challenge.md)
