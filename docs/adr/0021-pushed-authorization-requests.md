# ADR-0021: Pushed Authorization Requests (RFC 9126)

**Status**: Accepted
**Date**: 2026-07-08

## Context

Today every parameter of an authorization request travels in the front channel — the query string of a `GET /oauth/authorize` redirect, visible to the user-agent, browser history, server access logs, and any network intermediary. RFC 9126 lets a client instead POST the whole request to a new back-channel endpoint, get back a short-lived opaque `request_uri`, and send the user-agent to `/oauth/authorize` with just `client_id` and `request_uri` — the actual parameters never appear in a URL. This closes real problems: request tampering in transit, sensitive parameter leakage via `Referer` headers or browser history, and (for larger requests, e.g. RFC 9396 `authorization_details`) URL length limits.

The current authorize implementation:

- `Handler.Authorize` (`services/auth-server/internal/adapters/inbound/http/handler.go:345-378`) parses every parameter directly from the query string (`parseAuthorizeRequest`), validates it (`redirectURIMatches`, `validateAuthorizeParams`, `domain.ParseAuthorizationDetails`), and persists a `LoginChallenge`.
- There is no back-channel endpoint that accepts these same parameters ahead of the redirect, and no concept of a "pushed" request to consume at `/oauth/authorize` time.
- The authorization-code and login-challenge stores (ADR-0009, ADR-0011) already establish the exact pattern this needs: a domain repository interface, an in-memory adapter for local dev, a Redis adapter for production, atomic `Consume` (single-use, read-and-delete).

## Decision

Add `POST /oauth/par`. It accepts the same parameters `/oauth/authorize` accepts (as a form body instead of a query string), authenticates the client exactly as the token endpoint does, runs the identical parameter validation `/oauth/authorize` already runs, and returns `{request_uri, expires_in}`. `/oauth/authorize` gains a `request_uri` parameter: when present, the stored request is consumed and used in place of the query string.

### Request (RFC 9126 §2.1)

```
POST /oauth/par HTTP/1.1
Content-Type: application/x-www-form-urlencoded

response_type=code&client_id=...&client_secret=...&redirect_uri=...&scope=...
&state=...&code_challenge=...&code_challenge_method=S256
```

Client authentication is identical to `/oauth/token`'s: `Authorization: Basic` or `client_id`/`client_secret` form fields, resolved via the same `ports.ClientAuthenticator.Authenticate(ctx, clientID, clientSecret)` every grant strategy already calls. Confidential clients supply a secret; public clients supply `client_id` alone — `Authenticate` already distinguishes them (the client-registry-service public-client fix from earlier this platform's history). This endpoint does **not** reuse `readGrantClientCredentials`, which currently hardcodes a non-empty-secret requirement for every grant type except `token_exchange` — a pre-existing narrowing this ADR does not attempt to fix; PAR gets its own minimal credential-extraction helper that defers entirely to `Authenticate`.

### Response (RFC 9126 §2.2)

`201 Created`:
```json
{"request_uri": "urn:ietf:params:oauth:request_uri:<random>", "expires_in": 90}
```

`request_uri` is `urn:ietf:params:oauth:request_uri:` followed by 32 bytes of CSPRNG entropy, hex-encoded — same construction as the authorization code and login challenge IDs. TTL is 90 seconds (`AUTH_PAR_TTL_SECONDS`, default 90) — short enough that a leaked `request_uri` has a narrow exploitation window, long enough to cover the redirect from client to authorization server.

### Storage

```go
type PushedAuthorizationRequest struct {
    RequestURI           string
    ClientID             string
    ResponseType         string
    RedirectURI          string
    Scope                string
    State                string
    Nonce                string
    CodeChallenge        string
    CodeChallengeMethod  string
    Prompt               string
    MaxAge               string
    AuthorizationDetails  string // raw JSON, re-validated identically to the query-string path
    CreatedAt, ExpiresAt time.Time
}

func (p *PushedAuthorizationRequest) IsExpiredAt(now time.Time) bool { return !now.Before(p.ExpiresAt) }

type PushedAuthorizationRequestRepository interface {
    Save(ctx context.Context, req *PushedAuthorizationRequest) error
    Consume(ctx context.Context, requestURI string) (*PushedAuthorizationRequest, error)
}
```

Fields are stored as the raw form strings, not the parsed `authorizeRequest` struct — `/oauth/authorize`'s existing `parseAuthorizeRequest`/`validateAuthorizeParams`/`domain.ParseAuthorizationDetails` pipeline re-parses them identically whether they came from the query string or a consumed PAR record, so there is exactly one code path that turns raw strings into a validated request.

Two adapters, mirroring ADR-0009's authorization-code store exactly: `memory.PushedAuthorizationRequestRepository` (mutex + map, atomic `Consume`) for local dev, `redis.PushedAuthorizationRequestRepository` (Lua-script `GET`+`DEL`, key `par:<request_uri>`) for production, selected by the same `AUTH_REDIS_URL` branch already in `container.go`.

### `/oauth/authorize` changes

New query parameter `request_uri`. When present:

| # | Check | Failure |
|---|---|---|
| 1 | `client_id` also present (RFC 9126 §4 requires it alongside `request_uri`) | `invalid_request`, rendered directly (no redirect target established yet) |
| 2 | `repo.Consume(request_uri)` succeeds | `invalid_request`, rendered directly — an unknown/expired/already-consumed `request_uri` has no redirect target either |
| 3 | Stored `ClientID` equals the query's `client_id` | `invalid_request`, rendered directly — RFC 9126 §4's anti-injection binding |

After all three pass, the handler proceeds exactly as today using the *stored* parameters — any other query parameters present alongside `request_uri` are ignored (RFC 9126 §4). When `request_uri` is absent, behavior is byte-for-byte unchanged: this is an additive, opt-in path.

### Metadata (RFC 9126 §5)

`AuthorizationServerMetadata` gains `PushedAuthorizationRequestEndpoint` (`pushed_authorization_request_endpoint`), following the exact `RegistrationEndpoint`/`hasRegistration` conditional-emission pattern already used for RFC 7591's endpoint. This platform does not implement `require_pushed_authorization_requests` (a companion convention, not this RFC) — PAR is optional, not mandatory, matching how PKCE-mandatory-but-not-PAR-mandatory keeps this an additive capability rather than a breaking change to existing clients.

### Configuration surface

| Env var | Default | Purpose |
|---|---|---|
| `AUTH_PAR_TTL_SECONDS` | `90` | Pushed-request lifetime |

## Consequences

### Positive

- Closes a real information-leakage surface (query-string parameters in browser history, `Referer` headers, access logs) for any client that adopts it.
- Removes URL-length pressure on requests carrying `authorization_details` (RFC 9396) — a large JSON array no longer needs to survive query-string encoding and redirect-chain length limits.
- Additive: existing clients that never call `/oauth/par` see no behavior change at `/oauth/authorize`.
- Reuses every existing validation function (`validateAuthorizeParams`, `redirectURIMatches`, `domain.ParseAuthorizationDetails`) unchanged — the parameter-validation logic has exactly one implementation regardless of transport.

### Negative / Trade-offs

- A second store (mirroring the authorization-code and login-challenge stores) to operate and reason about. Cost is bounded — it's the same adapter shape already proven in production for two other short-lived record types.
- `/oauth/authorize`'s early-error paths for a bad `request_uri` cannot redirect to the client (no `redirect_uri` is known yet) — those errors render directly, which is a slightly different experience than the existing "redirect with `?error=`" path for parameter errors on the direct (non-PAR) flow. This matches RFC 9126's own model; there is no redirect target to use.

## Alternatives Considered

- **Make PAR mandatory (reject direct query-string authorize requests).** Rejected — that's a stricter profile (e.g. FAPI 2.0 Baseline), not what RFC 9126 itself requires, and would break every existing acceptance scenario and any real client that hasn't adopted PAR. Optional-and-additive is the correct default for a reference implementation.
- **Store the parsed `authorizeRequest` struct instead of raw form strings.** Rejected — storing raw strings means `/oauth/authorize`'s existing parsing/validation pipeline runs unmodified regardless of transport, so there is one code path to reason about instead of two subtly different ones (query-string parse vs. a hypothetical pre-parsed-struct path).
- **Reuse `readGrantClientCredentials` for PAR's client authentication.** Rejected — it hardcodes a non-empty-secret requirement for every grant except `token_exchange`, which would incorrectly reject public clients at the PAR endpoint. PAR gets a minimal, secret-optional credential reader that defers the actual accept/reject decision to `Authenticate`.

## References

- [RFC 9126 — OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
- [ADR-0009 — Authorization Code Grant with Mandatory PKCE](0009-authorization-code-pkce.md)
- [ADR-0011 — Login-UI Service and the Login-Challenge Handoff](0011-login-ui-service.md)
- [ADR-0012 — Authorization Server Metadata](0012-authorization-server-metadata.md)
- [ADR-0017 — Rich Authorization Requests (RFC 9396)](0017-rich-authorization-requests-rfc-9396.md)
