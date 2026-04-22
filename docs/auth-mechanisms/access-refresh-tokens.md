# Access Tokens & Refresh Tokens

## Overview

The access/refresh token pattern separates short-lived authorization credentials from long-lived renewal credentials. An **access token** authorizes API requests but expires quickly. A **refresh token** is used exclusively to obtain new access tokens without requiring the user to re-authenticate. This pattern is central to OAuth 2.0 ([RFC 6749 &sect;1.5](https://datatracker.ietf.org/doc/html/rfc6749#section-1.5)).

## How It Works

```
Client                     Auth Server                  Resource Server
  │                             │                             │
  │── POST /token ────────────▶│                             │
  │   grant_type=authorization_code                           │
  │   code=abc123                                             │
  │                             │                             │
  │◀── 200 OK ────────────────│                             │
  │   {                         │                             │
  │     "access_token": "at_...",                             │
  │     "refresh_token": "rt_...",                            │
  │     "expires_in": 900,      │                             │
  │     "token_type": "Bearer"  │                             │
  │   }                         │                             │
  │                             │                             │
  │── GET /api/resource ──────────────────────────────────── ▶│
  │   Authorization: Bearer at_...                            │
  │                             │                             │
  │◀── 200 OK ────────────────────────────────────────────── │
  │                             │                             │
  │                    *** access token expires ***            │
  │                             │                             │
  │── GET /api/resource ──────────────────────────────────── ▶│
  │   Authorization: Bearer at_...                            │
  │◀── 401 Unauthorized ─────────────────────────────────── │
  │                             │                             │
  │── POST /token ────────────▶│                             │
  │   grant_type=refresh_token  │                             │
  │   refresh_token=rt_...      │                             │
  │                             │                             │
  │◀── 200 OK ────────────────│                             │
  │   {                         │                             │
  │     "access_token": "at_new...",                          │
  │     "refresh_token": "rt_new...",                         │
  │     "expires_in": 900       │                             │
  │   }                         │                             │
```

1. The client authenticates and receives both an access token and a refresh token.
2. The client uses the access token for API requests.
3. When the access token expires, the client uses the refresh token to obtain a new pair.
4. The user never has to re-enter credentials until the refresh token itself expires or is revoked.

## Token Comparison

| Property | Access Token | Refresh Token |
|----------|-------------|---------------|
| Purpose | Authorize API requests | Obtain new access tokens |
| Lifetime | Short (5-60 minutes) | Long (hours, days, or weeks) |
| Sent to | Resource servers | Authorization server only |
| Format | Often JWT (self-contained) | Often opaque (server-side lookup) |
| Scope | Carries authorization scopes | May carry same or narrower scopes |
| Exposure risk | Lower (short-lived) | Higher (long-lived, high-value target) |

## Token Rotation

Refresh token rotation issues a new refresh token with every use and invalidates the old one:

```
Refresh Request #1:  rt_001 → new at + rt_002   (rt_001 invalidated)
Refresh Request #2:  rt_002 → new at + rt_003   (rt_002 invalidated)
Stolen replay:       rt_001 → DENIED (already used → revoke entire family)
```

If a previously used refresh token is presented, the authorization server detects reuse, which indicates theft. It revokes the entire token family, forcing the user to re-authenticate.

### Token Family Tracking

A **token family** is a chain of refresh tokens that originated from a single authorization grant. The server tracks the family ID and the latest valid token:

```
family_id: "fam_abc123"
  → rt_001 (used)
  → rt_002 (used)
  → rt_003 (current)
```

Reuse of any non-current token in the family triggers revocation of the entire family.

## Storage Guidelines

| Token | Where to Store | Why |
|-------|---------------|-----|
| Access token | Memory (JavaScript variable) | Limits exposure — cleared on page close |
| Refresh token | `HttpOnly`, `Secure`, `SameSite` cookie | Protected from XSS, automatically sent |
| Access token (mobile) | OS secure storage (Keychain / Keystore) | Hardware-backed protection |
| Refresh token (mobile) | OS secure storage (Keychain / Keystore) | Hardware-backed protection |

Never store either token in `localStorage` — it is accessible to any JavaScript on the page.

## Security Considerations

### Access Token Theft
- **Impact**: attacker can access resources until the token expires.
- **Mitigation**: keep lifetimes short (5-15 minutes). Use sender-constrained tokens (DPoP, mTLS) to bind tokens to the client.

### Refresh Token Theft
- **Impact**: attacker can obtain new access tokens indefinitely.
- **Mitigation**: use refresh token rotation, detect reuse, bind to client credentials, store securely.

### Scope Downscoping
A refresh token can issue access tokens with the same or narrower scope, never broader:

```
Original grant:  scope = "read write admin"
Refresh request: scope = "read"        → allowed (subset)
Refresh request: scope = "read delete" → denied  (delete not in original grant)
```

## When to Use

- Any OAuth 2.0 flow that involves user interaction (authorization code, device flow).
- SPAs and mobile apps where the user session should outlive the access token lifetime.
- APIs where you want short-lived access credentials but don't want the user to log in every 15 minutes.

## When Not to Use

- `client_credentials` grant — there is no user to "keep logged in." The client can simply request a new token when the current one expires.
- Environments where refresh tokens cannot be stored securely (pure client-side apps without a backend-for-frontend).

## Relevant RFCs

- [RFC 6749 &sect;1.5 — Refresh Token](https://datatracker.ietf.org/doc/html/rfc6749#section-1.5)
- [RFC 6749 &sect;6 — Refreshing an Access Token](https://datatracker.ietf.org/doc/html/rfc6749#section-6)
- [RFC 6819 — OAuth 2.0 Threat Model: Token Theft](https://datatracker.ietf.org/doc/html/rfc6819)
- [OAuth 2.0 Security Best Current Practice (draft-ietf-oauth-security-topics)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
