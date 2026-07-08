# ADR-0020: Authorization Server Issuer Identification (RFC 9207)

**Status**: Accepted
**Date**: 2026-07-08

## Context

RFC 9207 exists to stop *mix-up attacks*: a client that talks to more than one authorization server can be tricked into sending an authorization code (or an error) issued by AS-1 back to AS-2, if it has no way to verify which AS actually produced the response it received. The defense is trivial — every authorization response carries an `iss` parameter naming the issuing AS, and the client rejects any response whose `iss` doesn't match the AS it thinks it's talking to.

This platform has exactly one issuer today, so a mix-up attack has no live target. The gap is worth closing anyway: it's near-zero cost, and it's the difference between "this reference implementation models the full RFC 6749 §4.1.2.1 response shape" and "it's missing one field a real deployment with multiple issuers would need on day one."

The authorization response is split across two services in this platform's architecture, and both halves are missing `iss`:

- **`redirectAuthorizeError`** (`services/auth-server/internal/adapters/inbound/http/handler.go:667-686`) — the direct-to-client 302 for parameter errors detected *before* the login-ui handoff (RFC 6749 §4.1.2.1's error response). No `iss`.
- **`issueCodeResponse`** (`handler.go:452-456`, populated by `mintAndRespond`) — the internal `auth-server` → `login-ui` handoff response. No `iss`.
- **`redeemAndRedirect`** (`services/login-ui/internal/adapters/inbound/http/handler.go:241-273`) — the actual success redirect the relying party receives, built from `issueCodeResponse`'s fields. No `iss`.

The value to echo already exists: `cfg.JWT.Issuer` (`services/auth-server/internal/config/config.go:128`) is the same string already used for every JWT's `iss` claim and for RFC 8414 metadata's `issuer` field (`container.go` lines ~371, ~568) — clients already have a way to learn the expected value via discovery.

## Decision

Add `iss=<cfg.JWT.Issuer>` to every authorization response — both the error path auth-server issues directly, and the success path login-ui issues after redeeming the code. No new config surface: the existing `cfg.JWT.Issuer` is the value.

### Wire format (RFC 9207 §2)

Success (unchanged shape, `iss` added):
```
GET https://client.example/callback?code=abc123&state=xyz&iss=https%3A%2F%2Fauth.example.com
```

Error (unchanged shape, `iss` added):
```
GET https://client.example/callback?error=invalid_scope&state=xyz&iss=https%3A%2F%2Fauth.example.com
```

### Where it gets threaded

| Component | Change |
|---|---|
| `auth-server`'s `AuthorizeConfig` (handler.go) | New `Issuer string` field |
| `auth-server`'s `authorizeConfigFor` (container.go) | Sets `Issuer: cfg.JWT.Issuer` |
| `auth-server`'s `redirectAuthorizeError` | New `issuer string` parameter; sets `q.Set("iss", issuer)` when non-empty |
| `auth-server`'s `issueCodeResponse` | New `Issuer string` field (`json:"iss,omitempty"`), populated by `mintAndRespond` from `h.authorize.Issuer` |
| `login-ui`'s `issueCodeResponseDTO` / `ports.IssueCodeResponse` | New `Issuer string` field, decoded from auth-server's response |
| `login-ui`'s `redeemAndRedirect` | Sets `q.Set("iss", resp.Issuer)` alongside `code`/`state` when non-empty |

`iss` is omitted (not sent as an empty string) if `cfg.JWT.Issuer` is unset — matching how every other optional response parameter on this endpoint already behaves (`state`'s `if state != ""` guard in both `redirectAuthorizeError` and `redeemAndRedirect`). In practice `cfg.JWT.Issuer` is always configured (it's required for JWT signing), so `iss` is present on every real response.

### Metadata

No new RFC 8414 field. `issuer` already exists in the discovery document (RFC 8414 §2, already implemented per ADR-0012) — that's the exact value a client compares the response's `iss` against. RFC 9207 only concerns the authorization *response*, not discovery.

## Consequences

### Positive

- Closes a real, named attack class (mix-up attacks, RFC 9207 §1) for zero ongoing cost — one query parameter, one config value already in hand.
- Future-proofs the platform for a multi-issuer deployment (e.g. per-tenant issuers) without a second migration later.
- Both authorization-response paths (the early-error redirect and the post-login success redirect) get the same treatment — no asymmetry where one path is "mix-up-attack safe" and the other isn't.

### Negative / Trade-offs

- Touches two services (`auth-server` and `login-ui`) for one feature — the smallest change that's still fully correct, since the actual client-visible success response is assembled in `login-ui`, not `auth-server`.
- One more field to keep in sync across the internal `issue-code` JSON contract. Low risk: the contract already has two services agreeing on `code`/`redirect_uri`/`state`; `iss` is a fourth field of the same shape.

## Alternatives Considered

- **Add `iss` only to the error-redirect path auth-server owns directly, skip the login-ui success path.** Rejected — RFC 9207 §2 requires `iss` on *every* authorization response, and the success response is the one a legitimate client actually needs to check on the happy path. Protecting only the error path leaves the attack live for exactly the response a real client cares about most.
- **Add a new dedicated `AUTH_ISSUER_ID` config var instead of reusing `cfg.JWT.Issuer`.** Rejected — `cfg.JWT.Issuer` is already the AS's identity everywhere else (JWT `iss` claim, RFC 8414 `issuer` field). A second config knob for the same concept invites drift between the two if an operator only updates one.

## References

- [RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)
- [RFC 6749 §4.1.2.1 — Authorization Response](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1)
- [ADR-0011 — Login-UI Service and the Login-Challenge Handoff](0011-login-ui-service.md)
- [ADR-0012 — Authorization Server Metadata](0012-authorization-server-metadata.md)
