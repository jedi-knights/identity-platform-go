# ADR-0008: Use RS256 + JWKS for Access Token Signing

**Status**: Accepted
**Date**: 2026-06-23

## Context

Today all access tokens issued by `auth-server` are signed with **HS256** using a shared HMAC secret (`AUTH_JWT_SIGNING_KEY`). The same secret must be present on every service that validates tokens — `token-introspection-service` (`INTROSPECT_JWT_SIGNING_KEY`) and `example-resource-service` (`RESOURCE_JWT_SIGNING_KEY`). The shared library `github.com/jedi-knights/go-platform/jwtutil` hardcodes `jwt.SigningMethodHS256` in `Sign` and accepts only `*jwt.SigningMethodHMAC` in its parse keyfunc.

This design has three properties that block the work in the Planned RFC table of the root `CLAUDE.md` — RFC 7517 (JWKS), RFC 7518 (JWA), and indirectly RFC 7521/7523, RFC 9449, and OpenID Connect Core 1.0:

1. **Symmetric trust.** Every service that validates a token can also forge one. A compromise of any resource server compromises the issuer. For service-to-service traffic inside one organisation this is acceptable; for third-party MCP connectors, browser-delivered web apps, and any future federation use case (RFC 7523 JWT bearer assertions, OIDC RP), it is not.
2. **No key discovery.** Resource servers cannot retrieve the verification key from `auth-server` — the secret must be provisioned out of band. RFC 7517 (JWKS) and RFC 8414 (Authorization Server Metadata) both assume a public verification key is reachable over HTTP. Without that, OIDC clients and MCP connectors cannot auto-configure.
3. **No key rotation path.** Rotating `JWT_SIGNING_KEY` requires a coordinated restart of every service that holds it. There is no `kid` header to distinguish active and retiring keys, so a rotation window in which both old and new tokens must validate is unrepresentable.

The first feature that exposes this — finishing the `authorization_code` grant for MCP and a web app — turns these limits from theoretical into blocking. We need an asymmetric signing scheme with public-key discovery and a `kid`-based rotation path *before* user-facing tokens start being issued, so that no user-facing token is ever signed with HS256.

## Decision

Migrate access token signing to **RS256** (RFC 7518 §3.3) and expose the public verification keys at `/.well-known/jwks.json` (RFC 7517) on `auth-server`. Resource servers (`token-introspection-service`, `example-resource-service`, any future resource server) verify RS256 tokens by fetching and caching JWKS, keyed by the `kid` header.

### Signing algorithm

| Property | Value | Source |
|---|---|---|
| Signing algorithm | RS256 (RSASSA-PKCS1-v1_5 with SHA-256) | RFC 7518 §3.3 |
| Key size | 2048 bits minimum, 4096 supported | RFC 7518 §3.3 ("a key of size 2048 bits or larger MUST be used") |
| JOSE header `typ` | `at+jwt` | RFC 9068 §2.1 (unchanged from current) |
| JOSE header `kid` | string identifier for the active signing key | RFC 7517 §4.5 |
| JOSE header `alg` | `RS256` | RFC 7515 §4.1.1 |

RS256 is chosen over EdDSA / ES256 for one reason: maximum client library coverage. Every OAuth/OIDC client library shipping today supports RS256; ES256 is well-supported but not universal; EdDSA is excellent but still uneven in older toolchains. The reference implementation's job is to be reachable by every well-behaved client. The signing algorithm can be widened later by registering additional keys with different `alg` values in JWKS — that is forward-compatible.

### Key management

`auth-server` owns the signing keys. Two sources are supported:

1. **PEM env var** (`AUTH_RSA_PRIVATE_KEY_PEM`) — preferred for production. Operators generate `openssl genrsa -out key.pem 2048`, set the PEM as a Fly secret, and rotate by setting a second variable (see Rotation below). This keeps the key out of source control and survives container restarts.
2. **In-memory generation** (`AUTH_RSA_PRIVATE_KEY_PEM` unset) — fallback for local development and tests. `auth-server` generates a fresh 2048-bit RSA keypair at startup. Tokens signed by one container cannot be verified by another, which is acceptable for single-replica local development and consistent with the existing in-memory fallback pattern (ADR-0004).

Public keys are derived from the private key at startup and held in memory.

### JWKS endpoint

`auth-server` exposes `GET /.well-known/jwks.json` returning the active and retiring public keys per RFC 7517 §5:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "2026-06-23a",
      "n": "<base64url-modulus>",
      "e": "AQAB"
    }
  ]
}
```

The endpoint is **unauthenticated**, **cacheable** (response carries `Cache-Control: public, max-age=3600`), and **never includes private key material**. Only `kty`, `use`, `alg`, `kid`, `n`, and `e` per RFC 7517 §4.

### Key rotation

JWKS may contain multiple keys. `auth-server` signs only with the **current** key (the most recent by issue date); resource servers verify against **any** key in JWKS matched by `kid`. Rotation is therefore:

1. Operator sets `AUTH_RSA_PRIVATE_KEY_PEM_NEXT` to a freshly generated keypair.
2. `auth-server` reloads (rolling restart) — the new key becomes "current" and signs all new tokens; the previous key remains in JWKS as a "retiring" key.
3. Tokens issued before the rotation continue to validate against the retiring key for the remainder of the access token TTL.
4. After the access token TTL has fully elapsed, the operator removes `AUTH_RSA_PRIVATE_KEY_PEM` (the old current) and the retiring key drops out of JWKS on the next reload.

`kid` values are short and human-readable: ISO date + a one-letter disambiguator (`2026-06-23a`, `2026-06-23b`). Random IDs would be more uniform but less operationally legible during incident response.

### Resource server verification

Resource servers receive a new outbound port `ports.JWKSProvider`:

```go
type JWKSProvider interface {
    KeyByID(ctx context.Context, kid string) (*rsa.PublicKey, error)
}
```

The HTTP adapter for this port:

1. Fetches `GET <AUTH_JWKS_URL>/.well-known/jwks.json` once per cache TTL (default 1 hour, configurable via `RESOURCE_JWKS_CACHE_TTL`).
2. On a `kid` cache miss, performs an **out-of-cycle refresh** with a token-bucket rate limit (default: at most one refresh every 30 seconds). This handles the legitimate "key just rotated, our cache is stale" case without enabling a DoS via malformed `kid` values.
3. Returns `ErrUnknownKID` if the `kid` is not in JWKS after a refresh. The validator maps this to `{active: false}` for introspection (RFC 7662 §2.2) or `401` for the bearer middleware (RFC 6750 §3.1).

### Changes to `jwtutil`

The shared library needs three additions; the existing HS256 path stays in place to avoid breaking service-to-service callers that have not migrated yet. **All public-facing tokens (user-facing flows and resource-server-validated tokens after this ADR ships) must be RS256.** The HS256 path is kept only for the brief migration window.

```go
// SignRS256 signs claims with an RSA private key, embedding kid in the JOSE header.
func SignRS256(claims *Claims, privateKey *rsa.PrivateKey, kid string) (string, error)

// KeySource resolves the verification key for a given kid header.
// Implementations are typically JWKS-backed.
type KeySource func(ctx context.Context, kid string) (*rsa.PublicKey, error)

// ParseRS256 parses and validates a raw JWT signed with RS256, resolving the
// verification key via keySource based on the kid header. The keyfunc rejects
// any alg other than RS256 (RFC 8725 §3.1 — algorithm confusion).
func ParseRS256(ctx context.Context, raw string, keySource KeySource) (*Claims, error)
```

The new keyfunc enforces three things by construction:

- `alg` header is exactly `RS256` — no fallback to HS256 with the public key as the secret (RFC 8725 §3.1 algorithm confusion attack).
- `typ` header is `at+jwt` (preserved from existing behaviour).
- `kid` header is present and non-empty — tokens without a `kid` are rejected.

### Configuration surface

| Service | New env var | Default | Purpose |
|---|---|---|---|
| `auth-server` | `AUTH_SIGNING_ALG` | `RS256` | `RS256` (production) or `HS256` (legacy, deprecated) |
| `auth-server` | `AUTH_RSA_PRIVATE_KEY_PEM` | unset | Current signing key (PEM-encoded private key) |
| `auth-server` | `AUTH_RSA_PRIVATE_KEY_PEM_NEXT` | unset | Optional incoming key; promoted to current on next reload |
| `auth-server` | `AUTH_RSA_PRIVATE_KEY_PEM_PREVIOUS` | unset | Optional retiring key; published in JWKS but not used to sign |
| `token-introspection-service` | `INTROSPECT_JWKS_URL` | unset | When set, validate via JWKS; when unset, fall back to `INTROSPECT_JWT_SIGNING_KEY` |
| `token-introspection-service` | `INTROSPECT_JWKS_CACHE_TTL` | `1h` | JWKS cache TTL |
| `example-resource-service` | `RESOURCE_JWKS_URL` | unset | Same semantics as introspection |
| `example-resource-service` | `RESOURCE_JWKS_CACHE_TTL` | `1h` | JWKS cache TTL |

The fallback to HS256 when `JWKS_URL` is unset is intentional and matches the established pattern (ADR-0006, ADR-0007): a service can be brought up in isolation without the full stack. The fallback path is **not** for production.

### Compile-time interface check

The JWKS adapter follows ADR-0005:

```go
var _ ports.JWKSProvider = (*JWKSProvider)(nil)
```

## Consequences

**Positive**

- Resource servers can no longer forge tokens; only `auth-server` (the holder of the private key) can issue them. A compromised resource server cannot escalate to identity-platform-wide token issuance.
- MCP connectors, OIDC clients, and any future federated resource server can discover the verification key from `/.well-known/jwks.json` with no out-of-band provisioning.
- Key rotation is non-disruptive — the retiring key stays in JWKS until all tokens it signed have expired, removing the coordinated-restart requirement.
- Per-token `kid` makes rotation auditable: every token says which key signed it, and operators can correlate revocation/audit events with a specific key generation.
- Unblocks the rest of the Planned RFC table — every subsequent ADR (PKCE, OIDC, refresh rotation) assumes asymmetric signing.

**Negative / Trade-offs**

- RS256 signing is ~100× slower than HS256 (an HMAC vs. an RSA modular exponentiation). At typical token-issuance rates (≤ 100/s per replica) this is invisible; for a high-throughput issuer it would justify ES256 (~10× faster than RS256). Mitigation: this ADR keeps the algorithm choice in JWKS so a future ADR can register ES256 alongside RS256 without breaking deployed clients.
- Resource servers now have an outbound dependency on `auth-server` (or, in deployment, on whatever fronts JWKS). A `auth-server` outage during a JWKS cache miss returns `{active: false}` / `401`. Mitigated by: (a) the 1-hour default cache TTL — tokens validate offline for an hour after the last successful refresh, and (b) the failure mode is **fail-closed**, which is the correct security default.
- The JWKS endpoint is unauthenticated and unrate-limited at the HTTP layer. This is correct — it must be reachable by every client — but it puts `auth-server`'s availability story partly into the public-network surface. Mitigation: the response is fully cacheable (no per-request state), so a CDN or the `jk-api-gateway` cache absorbs all but the cache-fill traffic.
- One more configuration surface per service. Mitigated by the unset-means-fallback pattern that already exists across the platform.

## Alternatives Considered

- **Stay on HS256, add a key-derivation step so resource servers hold a derived secret rather than the master.** Removes the "any resource server can forge" property in principle but adds a custom KDF that has to be reviewed; standards-aligned clients (MCP, OIDC RPs) cannot speak it. Rejected — the cost of bespoke crypto exceeds the cost of migrating to a standard asymmetric scheme.
- **ES256 (ECDSA P-256) instead of RS256.** Faster signing, smaller keys, smaller signatures. Rejected as the default because client-library coverage for ES256 in the OIDC ecosystem is excellent but not yet universal — the reference implementation's job is to be maximally interoperable. ES256 can be added later as a second key in JWKS without breaking any existing client.
- **EdDSA (Ed25519).** Best modern choice cryptographically. Same library-coverage concern as ES256, more acute. Same forward-compatibility argument applies.
- **External KMS (AWS KMS, GCP KMS, HashiCorp Vault).** Production-grade key custody but introduces a runtime dependency on a cloud KMS for every token issuance. Out of scope for a reference implementation; the PEM-env-var path is the natural extension point — a future ADR can swap the in-memory `KeyProvider` for a KMS-backed one without touching the signing or JWKS code.
- **Stateful sessions instead of JWTs (drop the algorithm question entirely).** Solves the forgery problem by removing the signature, but loses the offline-verifiable property that resource servers and MCP connectors rely on. Out of scope — the platform's design centers on JWT-based authorization.
