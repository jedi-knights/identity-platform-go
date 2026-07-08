# ADR-0023: JWT-Bearer Client Authentication (RFC 7521 / RFC 7523)

**Status**: Accepted
**Date**: 2026-07-08

## Context

Every grant strategy in `services/auth-server/internal/application/grant_strategy.go` authenticates its caller by calling `ports.ClientAuthenticator.Authenticate(ctx, clientID, clientSecret)` — a shared secret is the only credential this platform accepts at the token endpoint today (`readGrantClientCredentials`, `services/auth-server/internal/adapters/inbound/http/handler.go`, reads it from HTTP Basic Auth or the form body).

A shared secret has a real operational cost for service-to-service clients: it must be provisioned out-of-band, rotated manually, and — because it is a bearer credential — is equally sensitive at rest in every system that holds it (CI secrets stores, config management, etc.). RFC 7521 (the generic assertion framework) and RFC 7523 (its JWT profile) let a client authenticate by presenting a JWT it signs with a private key, asserting its own identity (`iss`/`sub` = `client_id`) — the authorization server verifies the signature against a public key the client registered in advance. Nothing but a public key (or a URL to fetch one) ever needs to be shared, and the client can rotate its private key without any coordination with this platform.

This platform's public/private key infrastructure already exists for a different purpose — ADR-0008's RS256 access-token signing — but two pieces are still missing:

- **Per-client key material.** `domain.Client` (both `client-registry-service`'s `OAuthClient` and `auth-server`'s own `domain.Client`) has no field to hold a client's JWKS URI. RFC 7591 §2 defines `jwks_uri` as standard registration metadata; this platform's registration DTOs don't carry it.
- **Assertion verification.** `go-platform/jwtutil`'s `Parse`/`ParseRS256` functions hard-enforce the platform's own `typ: "at+jwt"` JOSE header (RFC 9068) — they exist to verify access tokens *this platform issued*, not third-party client assertions with no such header. A JWT-bearer assertion needs its own, simpler verification path: RS256-only, RFC 7523 §3's specific claim set, and replay protection via `jti`.
- **Per-client JWKS fetch.** `example-resource-service` and `token-introspection-service` each have a `jwks.Fetcher` that fetches and caches exactly one JWKS document from one URL fixed at process startup — this platform's own signing keys. RFC 7523 needs the opposite shape: fetch-and-cache *per client*, keyed by whatever `jwks_uri` that client registered.

## Decision

Add an optional `jwks_uri` field to client registration, a new `POST /internal/device/decision`-style verification path — really a new **authentication method**, not a new endpoint — usable alongside `client_secret` on the token endpoint's existing grant types.

### Scope — stated explicitly

1. **Only `client_credentials`, `refresh_token`, and `authorization_code`** gain JWT-bearer support in this ADR. `device_code`'s client already authenticates at the lower-frequency `/device_authorization` endpoint (secret or public-client, ADR-0022) and `token_exchange` already has its own public-client carve-out (ADR-0016) — both are lower-value targets for this specific credential upgrade and can adopt it in a follow-up ADR if a real need appears.
2. **`jwks_uri` only — not an embedded `jwks` document.** RFC 7591 §2 allows either. A URL is the more common production pattern (the client's own key-rotation story is "publish a new JWKS at the same URL"); an embedded key set would need its own rotation mechanism this ADR does not need to build.
3. **RS256 only.** Matches ADR-0008's existing asymmetric-signing precedent and RFC 8725 §3.1's algorithm-confusion guidance — no `alg: none`, no HS256 (a client's own secret has no role here; accepting HS256 would let a client "self-sign" with anything the server might mistake for a trusted key).
4. **`client_id` remains a required, separate request parameter** — it is not derived solely from the assertion's `sub` claim. See "Alternatives Considered" for why.

### Client registration

`client-registry-service`'s `domain.OAuthClient` gains:

```go
// JWKSURI is the URL this client publishes its public signing key(s) at,
// for JWT-bearer client authentication (RFC 7523). Empty means the
// client has not opted in — client_secret remains its only credential.
JWKSURI string `json:"jwks_uri,omitempty"`
```

Threaded through `CreateClientRequest`/`CreateClientResponse`/`GetClientResponse` and the RFC 7591 `RegistrationRequest`/`RegistrationResponse` DTOs (§2's `jwks_uri` is standard metadata this platform simply wasn't carrying). `auth-server`'s own `domain.Client` gets the same field, copied through by `clientregistry.ClientAuthenticator.toClient` exactly like every other client attribute.

### Wire format (RFC 7523 §2.2)

```
POST /oauth/token
grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<JWT>
&client_id=<client_id>
&scope=read
```

`domain.GrantRequest` gains `ClientAssertion` and `ClientAssertionType` fields, populated by `parseGrantRequest` from the form body unconditionally (empty for every existing request shape). `readGrantClientCredentials` waives the `client_secret`-required check when `client_assertion_type` is the JWT-bearer URN and `client_assertion` is non-empty — the same carve-out shape `token_exchange` already has, extended by one more condition.

### Assertion claims (RFC 7523 §3)

| Claim | Requirement |
|---|---|
| `iss` | MUST equal the `client_id` supplied in the request |
| `sub` | MUST equal the `client_id` supplied in the request |
| `aud` | MUST contain this platform's token-endpoint issuer (`cfg.JWT.Issuer`) |
| `exp` | MUST be present and in the future |
| `jti` | MUST be present, unique — enforced via replay protection below |

The assertion's `iss`/`sub` are checked against the request's `client_id` *after* signature verification succeeds — the client_id parameter is the primary identity signal (matching how `client_secret`-based auth already treats it), and the assertion must cryptographically corroborate it, not merely restate it.

### Verification flow

1. HTTP layer parses `client_assertion`/`client_assertion_type` into `GrantRequest` alongside the existing fields — no different from any other form parameter.
2. Each of the three in-scope grant strategies now resolves its client via a shared `authenticateClient` helper instead of calling `clientAuth.Authenticate` directly:
   ```go
   func authenticateClient(ctx context.Context, secretAuth ports.ClientAuthenticator, assertionAuth *ClientAssertionValidator, req domain.GrantRequest) (*domain.Client, error) {
       if req.ClientAssertion != "" {
           return assertionAuth.Authenticate(ctx, req.ClientID, req.ClientAssertion)
       }
       return secretAuth.Authenticate(ctx, req.ClientID, req.ClientSecret)
   }
   ```
3. `application.ClientAssertionValidator` (new, alongside the grant strategies — same architectural layer, not an adapter) does the actual work:
   - `ports.ClientLookup.Lookup(ctx, clientID)` — resolve the client and its `JWKSURI`. Empty `JWKSURI` → reject (`ErrUnauthorizedClient`-shaped — the client never opted in).
   - `ports.ClientJWKSFetcher.FetchKey(ctx, jwksURI, kid)` — new port, implemented by a new per-client, TTL-cached outbound adapter (`internal/adapters/outbound/jwks`). Structurally similar to `example-resource-service`'s `Fetcher` but keyed by URL rather than fixed at construction, since this platform must fetch a different JWKS per calling client rather than its own single signing key set.
   - Parse and verify the JWT (RS256 only, `golang-jwt/jwt/v5` directly — `jwtutil.ParseRS256` is unusable here, see Context) against the fetched key.
   - Validate `iss`/`sub`/`aud`/`exp` per the table above.
   - `domain.ClientAssertionReplayRepository.MarkUsed(ctx, jti, exp)` — new repository, atomic "record if absent." Memory adapter: mutex + map with lazy expiry. Redis adapter: `SET NX EX` — no Lua script needed, unlike every other atomic-consume repository in this codebase, because this is "insert once" rather than "read and delete."

### Configuration surface

No new environment variables. `cfg.JWT.Issuer` (already used as the access-token `iss` claim) doubles as the expected assertion `aud` value — this platform has one token endpoint, so its own issuer identifier is the correct audience a client's assertion should target.

## Consequences

### Positive

- Service-to-service clients (and any client with real key-management infrastructure) can authenticate without ever sharing a bearer secret with this platform — only a public key.
- `jwks_uri`-based rotation means a client can rotate its signing key unilaterally; the server picks up the new key on its next cache-expiry fetch.
- Reuses the existing `ports.ClientLookup`/`ClientAuthenticator` seam rather than inventing a parallel authentication pipeline — every grant strategy's audit/error-mapping behavior is unchanged for `client_secret` callers.

### Negative

- Three grant strategies each need a small constructor change (new `*ClientAssertionValidator` parameter) and their `validateClient`-equivalent helper rewired to the shared `authenticateClient` function — a cross-cutting change, unlike every prior ADR this session which touched exactly one new file cluster.
- A misbehaving or unreachable client JWKS endpoint fails that client's assertion-based requests (by design — there is no fallback to `client_secret` once a client presents an assertion). Operationally this pushes availability risk onto the client's own key-hosting, which is the correct tradeoff (the alternative is trusting a static key snapshot with no rotation).
- No support for embedded `jwks` (only `jwks_uri`) or non-RS256 algorithms — see Scope.

## Alternatives Considered

- **Derive `client_id` solely from the assertion's `sub` claim, making the `client_id` request parameter optional.** Rejected — every existing grant strategy already threads `req.ClientID` through downstream logic (refresh-token issuance, audit-event actor attribution) *before* any assertion would be parsed in some code paths. Requiring `client_id` as a request parameter and merely *corroborating* it against the verified assertion avoids touching every one of those call sites, at zero security cost (RFC 7523 permits either shape).
- **Support embedded `jwks` at registration time (RFC 7591 §2's alternative to `jwks_uri`).** Rejected for this ADR — see Scope. A URL is simpler to rotate and is what this ADR implements; embedded keys are a plausible follow-up.
- **Extend `device_code` and `token_exchange` in the same ADR.** Rejected — see Scope. Both have lower call volume or already have their own public-client story; extending them is a small follow-up once the shared `authenticateClient` helper exists.
- **Reuse `jwtutil.ParseRS256` for assertion verification.** Rejected — it hard-enforces the `at+jwt` JOSE header this platform's own access tokens carry (RFC 9068); a client assertion has no such header and would be rejected outright. A separate, RFC-7523-shaped parse path is simpler than relaxing `jwtutil`'s guarantees for its actual callers.

## References

- [RFC 7521 — Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7521)
- [RFC 7523 — JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523)
- [RFC 7591 §2 — OAuth 2.0 Dynamic Client Registration Protocol, Client Metadata](https://datatracker.ietf.org/doc/html/rfc7591#section-2)
- [RFC 8725 §3.1 — JWT Best Current Practices, Algorithm confusion](https://datatracker.ietf.org/doc/html/rfc8725#section-3.1)
- [ADR-0008 — RS256 + JWKS Token Signing](0008-rs256-jwks-token-signing.md)
- [ADR-0016 — Token Exchange (RFC 8693)](0016-token-exchange-rfc-8693.md)
