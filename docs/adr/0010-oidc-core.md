# ADR-0010: OpenID Connect Core 1.0

**Status**: Accepted
**Date**: 2026-06-23

## Context

ADR-0008 (RS256 + JWKS) and ADR-0009 (authorization code + PKCE) get the platform to "a user can log in and a client app can call an API on their behalf." That is OAuth 2.0. It is not yet *identity* — the client app receives an access token but no first-class identity assertion. It cannot answer "who is this user?" without an extra round trip, and the answer is not cryptographically tied to the login event the user just completed.

OpenID Connect Core 1.0 closes that gap by layering identity on top of the authorization code flow:

| Mechanism | What it adds |
|---|---|
| `openid` scope | Opt-in signal — request triggers OIDC mode; tokens become a *pair* (access token + ID token) |
| `id_token` | A second JWT carrying user identity claims, signed by the OP, audience-bound to the relying party (client) |
| `nonce` parameter | Round-trips authorize → id_token, lets the client detect ID token replay independently of any server-side state |
| `/userinfo` endpoint | Authenticated lookup of additional user claims using the access token — keeps the ID token small while making richer profile data available on demand |
| `at_hash` claim | Binds the ID token to the specific access token issued in the same response — prevents an attacker who steals one from forging the other |

The platform already has the substrate: `identity-service` owns the `User` record (`ID`, `Email`, `EmailVerifiedAt`, `Name`); ADR-0009 reserved the `Nonce` field on the authorization code record; ADR-0008 provides the signing key and JWKS for the ID token. What is missing is (a) the OIDC scope handling and ID-token issuance in `auth-server`, (b) a `/userinfo` endpoint, and (c) a port from `auth-server` to `identity-service` that fetches profile claims (the existing `UserAuthenticator` only authenticates — it does not return user attributes).

The `jwtutil` package needs one targeted change: today every JWT it signs carries `typ: at+jwt` (RFC 9068 §2.1 — correct for access tokens, wrong for ID tokens). ID tokens carry `typ: JWT` (or absent) per OIDC §2. `jwtutil` must support both shapes without losing the type-confusion defence that `at+jwt` provides for access tokens.

## Decision

Implement the **OpenID Connect Core 1.0** subset that browser apps, OIDC client libraries, and MCP connectors need: the `openid` scope, `id_token` issuance on the authorization code flow, `nonce` round-tripping, `/userinfo` lookup, and `at_hash` binding. Authentication strength claims (`acr`, `amr`) are included only at their minimal documented values; full ACR/AMR vocabularies are out of scope.

The authorization code flow is the **only OIDC response type** the platform supports — implicit, hybrid, and form_post response types are not implemented. This matches OAuth 2.1's deprecation of the implicit grant and keeps the surface focused.

### Scopes — what each maps to

OIDC scopes are additive on top of the existing scope handling. `openid` is the gateway scope; without it, no ID token is issued.

| Scope | Claims added | Source |
|---|---|---|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat`, `nonce`, `at_hash`, `auth_time`, `amr` | Required for any ID token |
| `profile` | `name`, `updated_at` | `User.Name`, `User.UpdatedAt` |
| `email` | `email`, `email_verified` | `User.Email`, `User.IsEmailVerified()` |

`address` and `phone` are not implemented in this ADR — the `User` model has no fields backing them, and adding them just to advertise empty claims would be misleading. They can be added in a later ADR when the user model grows.

Unrecognised scopes continue to follow the existing intersection rule (client must be registered for them); an unrecognised scope is rejected at the authorize endpoint per RFC 6749 §3.3.

### Token-endpoint behaviour with `openid`

When the authorization code's stored scopes include `openid`, `AuthorizationCodeStrategy.Handle` (see ADR-0009) issues both tokens in a single response:

```json
{
  "access_token":  "eyJ…",
  "token_type":    "Bearer",
  "expires_in":    3600,
  "refresh_token": "8f3a…",
  "scope":         "openid profile email",
  "id_token":      "eyJ…"
}
```

`GrantResponse` gains an `IDToken string` field with `json:"id_token,omitempty"`. Existing non-OIDC flows (no `openid` scope, `client_credentials`) leave the field empty and the JSON tag drops it from the response — backwards-compatible.

### ID token shape

| Claim | Value | Source |
|---|---|---|
| `iss` | OIDC issuer URL (e.g. `https://identity.example.com`) | `AUTH_OIDC_ISSUER` (or `AUTH_JWT_ISSUER` if it is already a URL) |
| `sub` | Stable user ID — `User.ID` from identity-service | `AuthorizationCode.Subject` |
| `aud` | Client ID of the relying party | `AuthorizationCode.ClientID` |
| `exp` | Issuance + ID-token TTL (default 5 min) | `now + AUTH_ID_TOKEN_TTL` |
| `iat` | Token issuance time | `now` |
| `auth_time` | Time the user actually authenticated | Set at `/oauth/authorize` (ADR-0011) and stored on the code |
| `nonce` | Echoed from authorize request | `AuthorizationCode.Nonce` (omitted when empty) |
| `at_hash` | First half of `SHA-256(access_token)` base64url-encoded — computed over the **final signed access token** (including any non-standard claims added by other ADRs, e.g. `code_jti` from ADR-0009, `family_id` from ADR-0014). Issuance order is: build access-token claims, sign, then hash the signed result for `at_hash`. | Computed at issuance |
| `amr` | Authentication methods | `["pwd"]` for password login (the only method currently) |
| `email` | User's email | `User.Email` (when `email` scope present) |
| `email_verified` | bool — was the email verified at issuance time? | `User.IsEmailVerified()` (when `email` scope present) |
| `name` | User's display name | `User.Name` (when `profile` scope present) |
| `updated_at` | Unix seconds | `User.UpdatedAt.Unix()` (when `profile` scope present) |

JOSE header:

| Field | Value |
|---|---|
| `alg` | `RS256` |
| `typ` | `JWT` (or absent) — *not* `at+jwt` |
| `kid` | Current signing key identifier from ADR-0008 |

ID-token TTL is short — 5 minutes (`AUTH_ID_TOKEN_TTL`, default `5m`). The ID token is meant for immediate consumption by the relying party, not for long-lived API access; that is the access token's job. Lengthening the TTL increases the value of a stolen ID token without adding any legitimate use case.

### Changes to `jwtutil`

The signing/parse path must distinguish access tokens from ID tokens by JOSE `typ`. Two additions:

```go
// SignIDToken signs an ID token JWT (typ: JWT) per OIDC Core §2.
// Same RS256 + kid mechanics as SignRS256, different typ header.
func SignIDToken(claims *IDClaims, privateKey *rsa.PrivateKey, kid string) (string, error)

// ParseIDToken parses an ID token, requiring typ to be "JWT" or absent.
// Rejects tokens carrying typ: at+jwt to prevent type-confusion (access token
// presented where ID token expected, or vice versa). Verifies signature via keySource.
func ParseIDToken(ctx context.Context, raw string, keySource KeySource, expectedAudience string) (*IDClaims, error)
```

`IDClaims` is a sibling of the access-token `Claims` type, carrying OIDC-specific fields (`Nonce`, `AtHash`, `AuthTime`, `AMR`, `Email`, `EmailVerified`, `Name`, `UpdatedAt`). It does not embed `Claims` — collapsing the two would let access-token-only fields like `roles` and `permissions` leak into ID tokens. Two types, one keyfunc convention.

The existing `Parse` / `ParseRS256` (which require `typ: at+jwt`) stay unchanged. The type-confusion defence is preserved on both sides: access-token validators reject ID tokens, and `ParseIDToken` rejects access tokens.

### `/userinfo` endpoint

`auth-server` exposes:

```
GET  /userinfo
POST /userinfo
```

Both methods MUST be accepted (OIDC §5.3.1). The endpoint:

1. Requires `Authorization: Bearer <access_token>` (RFC 6750 §3.1).
2. Validates the access token (signature, expiry, revocation — same path as `Introspect`).
3. Rejects the request with `403 insufficient_scope` if the `scope` claim does not contain `openid`.
4. Calls a new outbound port `ports.UserClaimsFetcher` against identity-service to retrieve the user record:

   ```go
   type UserClaimsFetcher interface {
       GetUserClaims(ctx context.Context, subject string) (*domain.UserClaims, error)
   }
   ```

5. Returns a JSON object containing **only** the claims permitted by the access token's `scope` (e.g. an access token issued with `openid email` returns `sub` and `email` but not `name`). The `sub` claim is always present.

The response shape mirrors the ID-token claim set, minus the protocol-level claims (`iss`, `aud`, `exp`, `iat`, `nonce`, `at_hash`):

```json
{
  "sub":            "user-1234",
  "email":          "alice@example.com",
  "email_verified": true,
  "name":           "Alice Liddell"
}
```

A new identity-service endpoint backs `UserClaimsFetcher`:

```
GET /users/{id}/claims
```

Returns the `UserClaims` projection (`ID`, `Email`, `EmailVerifiedAt`, `Name`, `UpdatedAt`). The endpoint is internal — protected by the same inter-service authentication used by `UserAuthenticator` (see `AUTH_IDENTITY_SERVICE_URL` pattern in CLAUDE.md). Fallback when `AUTH_IDENTITY_SERVICE_URL` is unset: `/userinfo` returns `503` rather than fabricating claims.

### Nonce handling

ADR-0009 already defined `AuthorizationCode.Nonce`. Three rules close out the contract:

1. **Storage**: the authorize endpoint (ADR-0011) stores `nonce` verbatim on the code record. Length is bounded to 1024 bytes; longer values are rejected.
2. **Echo**: when an ID token is issued from a code, the `nonce` claim is set to the stored value. If the original request had no `nonce`, the claim is omitted (not empty string).
3. **No server-side validation**: the server does not check the nonce against anything. The whole point is that the *client* uses the round-tripped value to detect ID token replay — server-side validation would defeat that.

### Configuration surface

| Service | New env var | Default | Purpose |
|---|---|---|---|
| `auth-server` | `AUTH_OIDC_ISSUER` | value of `AUTH_JWT_ISSUER` if URL-shaped, else error | OIDC `iss` claim and the `iss` in RFC 8414 metadata (ADR-0012) |
| `auth-server` | `AUTH_ID_TOKEN_TTL` | `5m` | ID-token lifetime |
| `auth-server` | `AUTH_IDENTITY_SERVICE_URL` (existing) | unset | When unset, `/userinfo` returns 503 and `profile`/`email` scopes are rejected at authorize |
| `identity-service` | (no new env var) | — | New `/users/{id}/claims` route is wired by default |

### Compile-time interface checks

```go
var _ ports.UserClaimsFetcher = (*UserClaimsFetcher)(nil)
```

## Consequences

**Positive**

- Web apps and MCP connectors can authenticate end-users using a standard OIDC client library. No bespoke "who am I" round trip after the auth code exchange — the ID token is the answer, signed and audience-bound.
- The `at_hash` binding plus `nonce` round-trip plus audience binding give the client three independent integrity signals on the ID token. Stealing one of (access token, ID token) does not let an attacker forge the other.
- `/userinfo` keeps the ID token small. Adding new profile fields later (address, phone, locale) is a `User` model change plus a `/userinfo` projection update — no protocol change.
- The `typ`-based separation between access tokens and ID tokens makes type-confusion attacks impossible at the signature layer, not just at the application layer.
- `identity-service` stays out of the OAuth protocol — it exposes a claims projection over a stable internal endpoint and nothing else. The boundary CLAUDE.md sets ("identity-service does not issue tokens") holds.

**Negative / Trade-offs**

- One more JWT issued per OIDC login means one more RS256 signing operation. At ~5ms per RS256 sign on commodity hardware, the cost is invisible at platform scale.
- `/userinfo` introduces another auth-server-to-identity-service hop. For high-frequency relying parties that call `/userinfo` on every page load, this matters; mitigation is in their hands — the ID token already carries `email`/`name` for normal use, and `/userinfo` is for explicit profile refreshes.
- `IDClaims` as a sibling of `Claims` doubles the canonical claim types in `jwtutil`. A single union type would be smaller code-wise but would let access-token-only fields drift into ID tokens through carelessness. Two types, enforced by the keyfunc `typ` check, is the better trade.
- The fixed `amr: ["pwd"]` value is honest today but will become inaccurate the moment a second authentication method (WebAuthn, MFA) is added. A future ADR introducing a second method must update the `amr` derivation; flagging it here so the assumption does not get baked into the implementation untested.
- `AUTH_OIDC_ISSUER` must be a URL; this is stricter than the current `AUTH_JWT_ISSUER` (which can be any string). Operators using non-URL issuer strings today must set the new variable explicitly. The startup validation explains the error and links to RFC 8414 §2.

## Alternatives Considered

- **Embed all profile claims in the ID token, skip `/userinfo`.** Simpler — one fewer endpoint, no UserClaimsFetcher. Rejected because the ID token then grows unbounded with every new claim, lives in the user-agent's URL fragment or storage for the session, and gets logged by intermediaries that have no business seeing PII. The `/userinfo` indirection is what makes ID tokens safe to forward and log.
- **Issue ID tokens for `client_credentials` too.** Some OIDC providers do this. Rejected because `client_credentials` has no user — `sub` would be the client ID, which is what the access token already says. An ID token without a user is misleading. Clients that want machine identity should call `/oauth/introspect` on the access token.
- **Support response_type `id_token` (implicit) or `code id_token` (hybrid).** OIDC defines them; modern clients do not need them. Rejected because the implicit flow leaks tokens through the URL fragment, OAuth 2.1 deprecates it, and supporting it would force the platform to defend against attacks (token leakage via referer, history, browser extensions) that the code flow already prevents.
- **Locate `/userinfo` on `identity-service`.** identity-service already owns the user data. Rejected because `/userinfo` must validate an OAuth access token, including scope and revocation, which makes the endpoint OAuth-protocol-aware. That violates the CLAUDE.md boundary that identity-service does not understand tokens. Keeping `/userinfo` on auth-server, with a thin projection endpoint on identity-service, preserves the separation.
- **Issue ID tokens that re-use the access-token claim type (`Claims`).** Saves a type. Rejected — see Trade-offs. The `roles`/`permissions` claims on `Claims` are not safe to leak through an ID token to relying parties, and `omitempty` is a weak guard against careless reuse.
