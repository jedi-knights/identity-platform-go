# ADR-0014: Refresh Token Rotation, Family Tracking, and Replay Detection

**Status**: Accepted
**Date**: 2026-06-23

## Context

Refresh tokens already rotate in this platform. `RefreshTokenStrategy.rotateRefreshToken` in `services/auth-server/internal/application/grant_strategy.go` deletes the presented refresh token and issues a new one on every use — RFC 6749 §6 rotation, fully implemented. That gets us halfway to OAuth 2.1 §6.1's requirement.

The other half is missing: **replay detection**. Today, if an attacker exfiltrates a refresh token from a victim's storage and the *attacker* uses it first, the legitimate client's next refresh fails (the token is gone) and the platform has no way to distinguish that failure from any other "token not found." The attacker walks away with a valid access token *and* a valid refresh token; the legitimate session quietly dies. The user experience is "I had to log in again, weird" — not "my account was attacked."

OAuth 2.1 §6.1 specifies the missing piece:

> If the authorization server detects an attempted re-use of an invalidated refresh token, the authorization server MUST revoke all refresh tokens issued based on the original authorization grant.

The "all refresh tokens issued based on the original authorization grant" wording is the standard **family** model. A family is the set of refresh tokens that descend from a single initial grant — every rotation produces a new family member; revoking the family revokes all members at once *and* (in our implementation) all access tokens issued from any of them. Replay detection requires keeping enough trace of consumed tokens to recognise their second presentation, which means rotation can no longer be a hard delete.

ADR-0009 introduced the `code_jti` claim for authorization-code replay detection — the same shape (a non-standard internal claim that lets a sweep revoke correlated tokens). This ADR introduces a sibling concept for refresh tokens.

## Decision

Replace the current delete-on-rotate refresh-token behaviour with **mark-consumed-on-rotate** plus **family tracking**. Every refresh token belongs to a family identified by a stable `family_id`; rotation produces a new active token in the same family and flips the old one to a consumed state. Presenting a consumed token is **replay**: the platform revokes the whole family and every access token issued from any of its members. Families have an absolute lifetime cap independent of the rolling per-token TTL.

### Refresh token state machine

```
              [issued]
                 │
                 ▼
              active ───── present at /oauth/token ───► consumed (new active token replaces it)
                 │                                              │
                 │                                              │ present again → REPLAY
                 │                                              ▼
                 │                                          family revoked
                 │                                              ▲
                 └────── family revoked by any path ────────────┘

         active / consumed → revoked (family-wide kill)
```

Three states: **active** (the current token), **consumed** (rotated out, kept until the family expires), **revoked** (family-wide kill or explicit /oauth/revoke). The transitions:

| From | To | Trigger |
|---|---|---|
| (nonexistent) | active | Initial issuance (authorization_code, client_credentials, ROPC if ever added) |
| active | consumed | Successful rotation at `/oauth/token` with `grant_type=refresh_token` |
| consumed | (family revoked) | Re-presentation of a consumed token at `/oauth/token` |
| active | (family revoked) | Re-presentation after the family was already revoked |
| any | revoked | `POST /oauth/revoke` for any token in the family |
| any | (purged) | TTL expiry (per-token TTL or family max-age, whichever fires first) |

The state field lives on the `RefreshToken` record. The Redis adapter retains the key after rotation (state flips from `active` to `consumed`); the in-memory adapter does the same. TTL on a consumed token is `family.MaxAgeExpiresAt - now`, so the consumed record outlives normal rotation cycles long enough to catch replay.

### Family record

A second key tracks the family itself:

```go
type RefreshTokenFamily struct {
    ID                string    // stable across the family's lifetime
    ClientID          string
    Subject           string
    Scopes            []string  // initial scopes; tightenable via consent revisit, never wideable
    CreatedAt         time.Time
    MaxAgeExpiresAt   time.Time // CreatedAt + AUTH_REFRESH_FAMILY_MAX_AGE
    CurrentTokenRaw   string    // the active member
    State             FamilyState // active | revoked
    MemberRaws        []string  // every token raw value ever issued in this family (for revocation sweep)
}

type FamilyState string

const (
    FamilyStateActive  FamilyState = "active"
    FamilyStateRevoked FamilyState = "revoked"
)
```

Stored under `refresh_family:<ID>` in Redis (or the in-memory map). `MemberRaws` grows by one per rotation; a 90-day family with 1-hour access token TTLs caps out at ~2160 entries — small enough to keep in a JSON blob without paging.

### Replay detection — the validation path

`RefreshTokenStrategy.validateRefreshToken` adds three checks ahead of the existing client-auth and expiry logic. Order matters: the family-state check must run before any token-existence check, so a replay attempt against a revoked family still triggers the revocation cascade (idempotently).

```
1. Family lookup
   ├── family not found              → invalid_grant
   ├── family.State == revoked       → invalid_grant (no cascade — already done)
   └── continue
2. Refresh token lookup
   ├── token not found AND family was once active → REPLAY DETECTED
   │   ├── revoke family (cascade)
   │   ├── log security event
   │   └── return invalid_grant
   ├── token.State == consumed       → REPLAY DETECTED (same cascade as above)
   ├── token.State == revoked        → invalid_grant
   └── continue
3. Standard expiry, client match, etc. (existing logic preserved)
```

The "token not found AND family was once active" branch is the one that catches the case where TTL has expired the consumed record but the family is still within its max-age window. Without it, a sufficiently delayed replay would be silently misattributed to a normal "expired token" error. The cost is one extra Redis lookup per refresh; the benefit is that the detection window matches the family's lifetime, not the per-token TTL.

### Revocation cascade

`RevokeFamily(ctx, familyID)` runs in three steps:

1. Set `family.State = revoked` (idempotent — a second revoke is a no-op).
2. Iterate `family.MemberRaws` and delete every refresh-token record. Errors on individual deletes are logged but do not halt the sweep.
3. Look up every access token carrying `family_id == familyID` and delete it. The Redis-backed token store uses a secondary index `family-tokens:<familyID>` (a Redis SET) populated on issuance; the in-memory store does a linear scan.

The order matters: family marked revoked first means a concurrent refresh attempt will see the revoked state and short-circuit. Member deletes second so the sweep is observable even if step 3 fails. Access token sweep last because it is the most expensive.

### `family_id` claim on access tokens

Access tokens issued from a refresh-token grant carry a new internal claim:

```json
{
  "iss": "...",
  "sub": "user-1234",
  "aud": "...",
  "exp": 1750003600,
  "iat": 1750000000,
  "family_id": "fam-abc123",
  "code_jti": "code-xyz789",
  "scope": "openid email read",
  ...
}
```

`family_id` is empty for `client_credentials` grants that bypass refresh rotation entirely (legacy fallback), and populated otherwise. Resource servers ignore it — it is internal. The token revocation sweep reads it to identify access tokens to delete during a family revocation.

The `Claims` type in `jwtutil` gains the `FamilyID string \`json:"family_id,omitempty"\`` field. `omitempty` keeps non-OAuth-2.1 tokens lean and backwards-compatible.

### Family creation

A new family is created at any of three points:

| Trigger | Existing flow | What this ADR changes |
|---|---|---|
| `authorization_code` exchange | Issues access + refresh | Also creates a new family; refresh token's `family_id` set to it |
| `client_credentials` (when refresh issued) | Issues access + refresh | Also creates a family (small one — only ever rotated by refresh_token grant) |
| `refresh_token` rotation | Issues access + refresh | **Reuses** the existing family — does NOT create a new one |

Rotation reusing the family is the load-bearing detail. If rotation created a new family, replay detection would not work — the consumed token's family would no longer be referenced by anything alive, and the cascade would have no chain to traverse.

### Family absolute lifetime cap

Refresh tokens can rotate indefinitely under RFC 6749. OAuth 2.1 §6.1 notes:

> [The AS] MAY choose to refresh the refresh token indefinitely or for a period of time. There is also the option of using sender-constrained refresh tokens... in which case the original authorization grant lifetime no longer matters.

Without sender-constrained tokens (we do not implement DPoP — separate future ADR), an indefinite refresh chain means a single successful login lets a session continue forever. That is the wrong default for an authentication system. This ADR introduces a **family max-age**: 90 days by default, configurable via `AUTH_REFRESH_FAMILY_MAX_AGE`. Once `family.MaxAgeExpiresAt` passes, the family becomes refresh-unusable — the user must re-authenticate. Individual tokens still validate until their per-token TTL expires.

The 90-day figure is the common industry default (Auth0, Okta, Google all sit in 90 days as a typical balance between user friction and exposure window). Operators with stricter or laxer requirements can override it.

### Storage shape changes

| Key | Lives in | Shape | TTL |
|---|---|---|---|
| `refresh_token:<raw>` | Redis | JSON refresh-token record incl. `state`, `family_id` | `MaxAgeExpiresAt - now` for consumed; `min(per-token TTL, family max-age)` for active |
| `refresh_family:<id>` | Redis | JSON family record | `MaxAgeExpiresAt - now` |
| `family-tokens:<id>` | Redis | SET of access-token JTIs | `MaxAgeExpiresAt + access-token-TTL - now` |

The two new keys (`refresh_family:`, `family-tokens:`) follow the existing namespacing convention from ADR-0006. The in-memory adapter mirrors the structure with maps + a slice; the Redis adapter uses native types.

**Redis namespace registry across ADRs** (confirming no overlap):

| Prefix | Owner | Source |
|---|---|---|
| `token:<raw>` | `auth-server` access tokens | ADR-0006 |
| `authcode:<raw>` | `auth-server` authorization codes | ADR-0009 |
| `authcode-tokens:<code_jti>` | `auth-server` access-token JTIs correlated to a code | ADR-0009 |
| `sso_session:<id>` | `login-ui` SSO sessions | ADR-0011 |
| `login_challenge:<id>` | `auth-server` login challenges | ADR-0011 |
| `csrf:<id>` | `login-ui` CSRF tokens | ADR-0011 |
| `refresh_token:<raw>` | `auth-server` refresh tokens (this ADR) | ADR-0014 |
| `refresh_family:<id>` | `auth-server` refresh-token families (this ADR) | ADR-0014 |
| `family-tokens:<id>` | `auth-server` access-token JTIs correlated to a family (this ADR) | ADR-0014 |

All prefixes are distinct. Any future ADR that adds a Redis-backed store must extend this registry.

### Compile-time interface checks

```go
var _ domain.RefreshTokenRepository = (*RefreshTokenRepository)(nil)
var _ domain.RefreshTokenFamilyRepository = (*RefreshTokenFamilyRepository)(nil)
```

### Composition with ADR-0009's `code_jti` cascade

Access tokens issued in this flow can carry both `code_jti` (from ADR-0009) and `family_id` (this ADR) when they descend from an authorization-code grant that has subsequently been refreshed. The two cascades target different attack vectors and fire on different events; they do not interfere:

| Event | Cascade that fires | Cascade that does NOT fire |
|---|---|---|
| Authorization code re-presented at `/oauth/token` | `code_jti` cascade (ADR-0009) — delete every token whose `code_jti` matches | `family_id` cascade — the refresh-token grant flow is not entered |
| Refresh token re-presented at `/oauth/token` (consumed or post-family-revoke) | `family_id` cascade (this ADR) — revoke family, delete every token whose `family_id` matches | `code_jti` cascade — the code was already consumed long ago |
| Explicit `POST /oauth/revoke` for any token | Neither cascade — the single token is deleted; family/code state untouched | (both) |

The set of access tokens affected by the two cascades overlaps but never inverts. A family cascade will delete every access token with a matching `family_id`, and any of those tokens may also have had a `code_jti`. That is fine — both indices point to the same record, and `DELETE` is idempotent (the Redis `DEL` and the in-memory `map.delete` both no-op on missing keys). No double-delete error, no double-counted security event.

The order is: the cascade triggered by the detection event runs in its entirety. If the same token is also reachable via the other index, the deletion sweep simply finds the key already gone. The two indices are maintained independently — issuance writes both `authcode-tokens:<code_jti>` and `family-tokens:<family_id>` when applicable — so the cleanup is correct regardless of which cascade ran.

### Backwards compatibility

Refresh tokens issued before this ADR ships have no `family_id` and no family record. The validation path treats an empty `family_id` as a single-token family — replay against the legacy token returns `invalid_grant` like today, but no cascade is possible (there is no family to revoke). Once the legacy token rotates for the first time, the new active token is issued with a fresh `family_id` and the family state begins.

This is a one-rotation window of degraded replay detection for tokens already in flight at upgrade time. Acceptable: refresh tokens are short-lived enough that the population drains in days, and the threat model the new logic defends against (refresh-token leak) doesn't suddenly become more likely on the upgrade day.

### Configuration surface

| Variable | Default | Purpose |
|---|---|---|
| `AUTH_REFRESH_FAMILY_MAX_AGE` | `2160h` (90 days) | Absolute lifetime for a refresh-token family. After this, the user must re-authenticate. |
| `AUTH_REFRESH_TOKEN_TTL` | `720h` (30 days) — existing | Per-token TTL. Continues to apply per rotation; capped by `AUTH_REFRESH_FAMILY_MAX_AGE`. |

`AUTH_REFRESH_TOKEN_TTL` is the existing knob renamed for clarity. The defaults imply: a long-running session refreshes every 30 days at most (the access token's hourly cycle pulls a new refresh token along) and is force-re-authenticated at 90 days.

## Consequences

**Positive**

- A leaked refresh token now triggers a detectable, recoverable failure. The first use by the attacker rotates normally; the legitimate client's next use is the replay event, and within milliseconds every token derived from the compromised chain is revoked.
- The family model gives operators a clean "kill this session" primitive — calling `RevokeFamily` from an admin tool (future work) terminates a single login completely, without affecting the user's other concurrent sessions.
- The absolute lifetime cap bounds the cost of a refresh-token leak: even if replay detection misses (e.g. attacker uses the token and the victim never refreshes again), the maximum window is `AUTH_REFRESH_FAMILY_MAX_AGE`, not "forever."
- Combined with ADR-0009's `code_jti` cascade, the platform now has retroactive containment at two layers: code-level (any token issued from a replayed code is revoked) and family-level (any token issued from a replayed refresh token is revoked).
- The `family_id` claim is invisible to resource servers — adding it is a backwards-compatible JWT extension. RS256 + JWKS (ADR-0008) means the change ships at the issuer with no resource-server coordination.

**Negative / Trade-offs**

- Refresh-token storage is now bigger. Each family carries N consumed token records (one per rotation) plus the active token plus the family record itself. At 90-day families with hourly rotations, that is up to ~2160 records per family. For a 100 K-user platform with one family per user, ~216 M Redis keys at peak — non-trivial. Mitigation: the per-token TTL on consumed records can be tuned shorter than the family max-age, trading some replay detection window for storage. The defaults assume detection-over-storage; production deployments are expected to revisit.
- The "token not found AND family active" branch makes the validation path slightly slower (two lookups instead of one). At nominal QPS this is invisible; under attack (mass replay attempts) the Redis hit rate may matter. Mitigation: the family lookup is keyed by a short ID that the active refresh token carries — one fast `GET` per attempt.
- The 90-day family cap is a UX/security trade-off. Users with very long-running browser sessions will be surprised by an unexpected re-login event. The trade is deliberate; documenting it in `login-ui` (next ADR work) is on the to-do list.
- `family_id` adds one more non-standard claim to access tokens alongside `code_jti` (ADR-0009). Tokens are still small (<1 KB typical) but every internal claim is a future migration cost if the scheme changes. Keeping both is justified because they catch distinct attack patterns; collapsing them would weaken one or both.
- The cascade's "iterate every access token" step is O(N) in the family's access-token issuance count. The Redis secondary index reduces it to O(1) lookup of a SET; the in-memory adapter still scans. Acceptable: the in-memory adapter is for local development, where families are small and the scan is microseconds.

## Alternatives Considered

- **Keep delete-on-rotate; rely on the existing "not found" failure to surface the leak.** What we have today. Rejected because it provides no positive detection signal — the legitimate client's failure is indistinguishable from a normal expiry, and the attacker's session continues silently. OAuth 2.1 explicitly requires the family-revocation behaviour.
- **Tombstone consumed tokens with a much shorter TTL** (e.g. 5 minutes). Cheaper storage. Rejected because the detection window then becomes 5 minutes, which is exactly when a leaked refresh token from a long-idle device shows up. The 90-day family-aligned TTL is the right default; operators can tune down if storage is a constraint.
- **Sender-constrained refresh tokens (DPoP, RFC 9449)** instead of family tracking. Strongest defence — a stolen refresh token cannot be replayed because the holder also needs the proof-of-possession key. Rejected for this ADR: DPoP is in the Considered RFC table in CLAUDE.md and has its own design space (key binding, key rotation, replay nonces). Family tracking complements rather than replaces DPoP; both can ship.
- **Bind refresh tokens to a device fingerprint or IP.** Cheap, weak. Rejected — fingerprints break with browser updates and IPs break with mobile networks. The false-positive rate would force operators to disable the check, leaving the platform back where it started.
- **Use the same `code_jti` claim from ADR-0009 instead of a separate `family_id`.** Tempting symmetry. Rejected because `code_jti` identifies the *issuance event*, not the rotation chain — two refresh tokens that happen to derive from the same authorization code share a `code_jti`, but a refresh-token grant has no `code_jti` of its own to copy forward. The semantics are distinct; sharing the claim would let a single attack vector compromise both layers.
- **Make refresh-token TTL = family max-age (no per-token TTL).** Simpler — one knob. Rejected because the per-token TTL is what bounds the exposure of any single stolen refresh token; eliminating it means a refresh token leaked on day 1 is usable for 90 days unless replay detection fires. The two-level TTL is the right shape.
