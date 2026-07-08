# ADR-0022: Device Authorization Flow (RFC 8628)

**Status**: Accepted
**Date**: 2026-07-08

## Context

RFC 8628 exists for browserless or input-constrained devices (CLIs, IoT, smart TVs) that cannot receive a redirect: the device requests a `device_code` + short human-readable `user_code`, displays the `user_code` and a verification URL to the user, and polls the token endpoint while the user visits that URL on a *different*, browser-capable device to approve the request.

This platform's `authorization_code` grant (ADR-0009) and login-challenge handoff (ADR-0011) already establish the pieces this needs:

- The Strategy pattern extension point (`services/auth-server/CLAUDE.md`'s documented recipe: constant in `grant.go`, `GrantStrategy` implementation, container registration).
- A short-lived, single-use, repository-backed record pattern (`domain.AuthorizationCode`, `domain.PushedAuthorizationRequest`) — memory + Redis adapters, atomic `Consume`.
- A precedent for `login-ui` hosting a user-facing page that calls back into `auth-server` via a bearer-authed internal endpoint (`/internal/issue-code`, ADR-0011).

None of this exists yet for device flow: there's no `device_code` grant type, no `/device_authorization` endpoint, and no verification page.

## Decision

Add `POST /device_authorization` (auth-server), a new `device_code` grant strategy, and a minimal verification page on `login-ui` where a signed-in-inline user enters the `user_code` and approves or denies.

### Scope reduction — stated explicitly

Two simplifications, both deliberate:

1. **No `slow_down` enforcement.** RFC 8628 §3.5 allows (not requires) the server to demand a larger polling interval when the client polls too fast. Enforcing it needs additional poll-timestamp tracking machinery with no protocol-correctness payoff — `authorization_pending`/`access_denied`/`expired_token`/successful redemption are the behaviors that actually prove the flow works. A future ADR can add it if a concrete abuse case appears.
2. **No separate consent screen.** The verification page combines "who's requesting access" display, re-authentication, and approve/deny into one form — mirroring how `/internal/issue-code`'s own doc comment already notes consent narrowing is deferred ("sending nil — auth-server treats nil as grant the recorded scopes"). A dedicated scope-narrowing consent UI is out of scope here for the same reason it's out of scope there.

### Request/response shapes

`POST /device_authorization` (RFC 8628 §3.1) — form body, client authentication identical to PAR's (ADR-0021): `ports.ClientAuthenticator.Authenticate`, so public clients (no secret) and confidential clients both work.
```
POST /device_authorization
client_id=...&client_secret=...&scope=read
```
Response (RFC 8628 §3.2), `200 OK`:
```json
{
  "device_code": "<opaque, 256 bits entropy>",
  "user_code": "<8 chars, uppercase+digits, no ambiguous glyphs, formatted XXXX-XXXX>",
  "verification_uri": "<login-ui base>/device",
  "verification_uri_complete": "<verification_uri>?user_code=<user_code>",
  "expires_in": 600,
  "interval": 5
}
```

`user_code` uses a 32-character alphabet excluding visually ambiguous characters (`0/O`, `1/I/L`) — RFC 8628 §6.1 recommends this for a code a human re-types from one screen to another.

### Storage

```go
type DeviceAuthorizationStatus string

const (
    DeviceAuthorizationPending  DeviceAuthorizationStatus = "pending"
    DeviceAuthorizationApproved DeviceAuthorizationStatus = "approved"
    DeviceAuthorizationDenied   DeviceAuthorizationStatus = "denied"
)

type DeviceAuthorization struct {
    DeviceCode string
    UserCode   string
    ClientID   string
    Scope      string
    Status     DeviceAuthorizationStatus
    Subject    string // set on approval
    Interval   int
    CreatedAt  time.Time
    ExpiresAt  time.Time
}

type DeviceAuthorizationRepository interface {
    Save(ctx context.Context, auth *DeviceAuthorization) error
    // FindByDeviceCode is read-only — polling must be able to observe
    // "still pending" repeatedly without consuming the record.
    FindByDeviceCode(ctx context.Context, deviceCode string) (*DeviceAuthorization, error)
    // FindByUserCode backs the verification page's lookup.
    FindByUserCode(ctx context.Context, userCode string) (*DeviceAuthorization, error)
    Approve(ctx context.Context, userCode, subject string) error
    Deny(ctx context.Context, userCode string) error
    // Consume atomically reads and deletes — called only after polling
    // observes Status == approved, so a racing second poll (or a replay
    // of an already-redeemed device_code) sees "not found" and the
    // strategy reports expired_token, never issuing a second token pair.
    Consume(ctx context.Context, deviceCode string) (*DeviceAuthorization, error)
}
```

Two adapters, mirroring `PushedAuthorizationRequestRepository` (ADR-0021): memory (mutex + two maps — `byDeviceCode` and a `userCode → deviceCode` index, one lock covers both so `Approve`/`Deny` and `Consume` stay atomic) and Redis (JSON blob under `devicecode:<device_code>`, a plain string index key `devicecode-by-usercode:<user_code>`, `Consume` reusing the existing `consumeScript` Lua GET+DEL). TTL: `AUTH_DEVICE_CODE_TTL_SECONDS`, default 600 (RFC 8628 §3.2's example).

### Polling (`grant_type=urn:ietf:params:oauth:grant-type:device_code`)

| Stored status | Response |
|---|---|
| Not found / expired | `expired_token` |
| `pending` | `authorization_pending` |
| `denied` | `access_denied` |
| `approved` | `Consume`, then issue access + refresh token for `Subject`/`Scope`/`ClientID` — mirrors `AuthorizationCodeStrategy.issueTokens`' shape (no ID token; device flow has no OIDC redirect leg to carry a `nonce`) |

All four map to `ErrInvalidGrant` at the strategy layer (RFC 8628 §3.5's codes are a refinement of `invalid_grant`, same as this platform's existing coarse-grained `ErrInvalidGrant` philosophy for the authorization_code grant) — the HTTP layer's `writeTokenError` gains a case that reads the specific code back out via a typed error, the same promotion `unsupportedTokenType` got when a second call site needed it (ADR-0009's precedent: promote to a named constant only once something other than a single inline string needs it).

### Verification page (`login-ui`)

`GET /device` renders a form: `user_code`, `email`, `password`, and Approve/Deny submit buttons. `POST /device`:
1. Verifies credentials via the existing `ports.UserAuthenticator` (the same port `/sign-in` uses).
2. On approve, calls a new bearer-authed `auth-server` endpoint `POST /internal/device/decision` with `{user_code, subject, approved: true}` — same shared-secret authentication as `/internal/issue-code` (`AUTH_LOGIN_UI_SERVICE_TOKEN`).
3. Renders a static confirmation page ("Device approved — you can return to your device.") — there is nothing to redirect to; the device is polling independently.

`verification_uri_complete` pre-fills `user_code` via a query parameter so a clickable link (or QR code, not implemented here) skips that field.

### Metadata

`AuthorizationServerMetadata` gains `DeviceAuthorizationEndpoint` (RFC 8628 §4), advertised unconditionally like `AuthorizationEndpoint`/`TokenEndpoint`/PAR's endpoint (ADR-0021's precedent) — the URL is stable even in a config where the endpoint's dependencies aren't fully wired.

### Configuration surface

| Service | Env var | Default | Purpose |
|---|---|---|---|
| `auth-server` | `AUTH_DEVICE_CODE_TTL_SECONDS` | `600` | Device/user code lifetime |
| `auth-server` | `AUTH_DEVICE_POLL_INTERVAL_SECONDS` | `5` | Advertised minimum polling interval |
| `login-ui` | (reuses `LOGIN_UI_AUTH_SERVER_URL` + `LOGIN_UI_AUTH_SERVER_SERVICE_TOKEN`) | — | Same outbound credentials `/internal/issue-code` already uses |

## Consequences

### Positive

- Closes a real gap: this platform previously had no answer for CLI tools, IoT devices, or any client without a redirect-capable browser.
- Reuses every established pattern (Strategy, repository-with-atomic-Consume, login-ui-calls-back-via-internal-endpoint) rather than inventing new ones — the review surface for this ADR is "does it apply the existing patterns correctly," not "is this a new architecture."
- `verification_uri_complete` makes the common case (device displays a clickable link or QR code) a one-tap flow even though this reference implementation doesn't render a QR code itself.

### Negative / Trade-offs

- No `slow_down` enforcement (stated above) — a misbehaving client that polls faster than `interval` is not penalized, only relies on the client following the spec's advertised interval voluntarily. Acceptable for a reference implementation; a production deployment fronting untrusted clients should add it.
- The verification page's combined auth+approve form is less polished than a real product's "you're signed in, just click Approve" experience — a signed-in-already user still re-enters credentials. Matches this platform's existing stance that a dedicated SSO-aware consent UI is a separate, not-yet-built concern (ADR-0011's own "What this ADR does NOT define").
- Two new outbound/inbound endpoints (`/internal/device/decision` on auth-server, `/device` on login-ui) to keep in sync, same shape as the existing `/internal/issue-code` pair.

## Alternatives Considered

- **Route device flow through the existing `LoginChallenge`/`/oauth/authorize` machinery instead of a parallel `DeviceAuthorization` store.** Rejected — `LoginChallenge` is keyed to a single browser redirect round-trip with a `redirect_uri`; device flow has no redirect at all and needs long-lived polling semantics `LoginChallenge` was never designed for. A parallel, purpose-built store is simpler than retrofitting redirect-shaped state to a no-redirect flow.
- **Enforce `slow_down`.** Rejected for now — see Negative/Trade-offs; revisit if abuse is observed.
- **Full consent screen showing requested scopes before approval.** Rejected — consistent with ADR-0011's existing deferral of the same concern for the browser-based authorization_code flow.

## References

- [RFC 8628 — OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [ADR-0009 — Authorization Code Grant with Mandatory PKCE](0009-authorization-code-pkce.md)
- [ADR-0011 — Login-UI Service and the Login-Challenge Handoff](0011-login-ui-service.md)
- [ADR-0021 — Pushed Authorization Requests](0021-pushed-authorization-requests.md)
