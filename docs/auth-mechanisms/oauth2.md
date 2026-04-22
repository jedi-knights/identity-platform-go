# OAuth 2.0

## Overview

OAuth 2.0 is an authorization framework that enables a third-party application to obtain limited access to a resource on behalf of a user — without the user sharing their credentials with the third party. It is defined in [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749).

OAuth 2.0 answers the question: **"Can this application access this user's data?"** — not "Who is this user?" (that is OpenID Connect's job).

## Roles

| Role | Description | Example |
|------|-------------|---------|
| **Resource Owner** | The user who owns the data | A GitHub user |
| **Client** | The application requesting access | A CI/CD tool that reads repos |
| **Authorization Server** | Issues tokens after authenticating the resource owner | GitHub's OAuth server |
| **Resource Server** | Hosts the protected resources, validates tokens | GitHub's API |

## Grant Types

OAuth 2.0 defines several flows (grant types) for different client types and deployment scenarios.

### Authorization Code (with PKCE)

The most common and most secure flow. Used by web apps, mobile apps, and SPAs.

```
User           Client              Auth Server           Resource Server
 │               │                      │                      │
 │── click ────▶│                      │                      │
 │               │── GET /authorize ──▶│                      │
 │               │   response_type=code │                      │
 │               │   client_id=...      │                      │
 │               │   redirect_uri=...   │                      │
 │               │   code_challenge=... │                      │
 │               │   state=xyz          │                      │
 │               │                      │                      │
 │◀──────────── │◀── login page ──────│                      │
 │── credentials ────────────────────▶│                      │
 │               │                      │                      │
 │◀──────────── │◀── redirect ────────│                      │
 │               │   ?code=abc&state=xyz│                      │
 │               │                      │                      │
 │               │── POST /token ─────▶│                      │
 │               │   grant_type=        │                      │
 │               │     authorization_code                      │
 │               │   code=abc           │                      │
 │               │   code_verifier=...  │                      │
 │               │                      │                      │
 │               │◀── access_token ────│                      │
 │               │                      │                      │
 │               │── GET /api ────────────────────────────────▶│
 │               │   Authorization: Bearer ...                 │
 │               │◀── 200 OK ─────────────────────────────────│
```

**PKCE** (Proof Key for Code Exchange, [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)) prevents authorization code interception attacks. The client generates a random `code_verifier`, sends its hash (`code_challenge`) in the authorization request, and proves possession of the verifier when exchanging the code for a token.

### Client Credentials

Machine-to-machine authentication. No user involved — the client authenticates itself and receives a token for its own resources.

```
Client                          Auth Server
  │                                │
  │── POST /token ───────────────▶│
  │   grant_type=client_credentials│
  │   client_id=...                │
  │   client_secret=...            │
  │   scope=read write             │
  │                                │
  │◀── 200 OK ───────────────────│
  │   { "access_token": "..." }    │
```

### Device Authorization

For devices with limited input capability (smart TVs, CLI tools, IoT devices). Defined in [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628).

```
Device              Auth Server              User (on phone/laptop)
  │                      │                         │
  │── POST /device ────▶│                         │
  │   client_id=...      │                         │
  │                      │                         │
  │◀── device_code, ────│                         │
  │    user_code,        │                         │
  │    verification_uri  │                         │
  │                      │                         │
  │   Display: "Go to    │                         │
  │   example.com/device │                         │
  │   Enter code: ABCD"  │                         │
  │                      │◀── enter code ─────────│
  │                      │◀── approve ────────────│
  │                      │                         │
  │── POST /token ──────▶│  (polling)              │
  │   grant_type=         │                         │
  │   urn:...:device_code │                         │
  │   device_code=...     │                         │
  │                      │                         │
  │◀── access_token ────│                         │
```

### Refresh Token

Not a standalone flow — it is used alongside other grants to obtain new access tokens without re-authentication. See [access-refresh-tokens.md](access-refresh-tokens.md).

### Implicit (Deprecated)

The implicit flow returned tokens directly in the URL fragment. It is **deprecated** by the [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics) due to token leakage risks. Use authorization code + PKCE instead.

### Resource Owner Password Credentials (Deprecated)

The client collects the user's username and password directly. This defeats the purpose of OAuth (delegated access without sharing credentials). **Deprecated** — use authorization code flow instead.

## Key Concepts

### Scopes

Scopes limit what an access token can do. They are requested by the client and granted (fully or partially) by the authorization server.

```
Request:  scope=read write delete
Granted:  scope=read write          (delete was denied)
```

Scopes are space-delimited strings in the token and request. The resource server enforces scope restrictions.

### State Parameter

A random value sent in the authorization request and verified in the callback. Prevents CSRF attacks against the redirect URI.

### Redirect URI

The URL the authorization server redirects to after user approval. Must exactly match a pre-registered URI — open redirectors enable token theft.

### Client Types

| Type | Description | Example | Authentication |
|------|-------------|---------|---------------|
| Confidential | Can securely store a secret | Server-side web app | `client_id` + `client_secret` |
| Public | Cannot store a secret | SPA, mobile app, CLI | `client_id` only (use PKCE) |

## Token Endpoint Response

```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "rt_dGhpcyBpcyBh...",
  "scope": "read write"
}
```

Required headers on every token response ([RFC 6749 &sect;5.1](https://datatracker.ietf.org/doc/html/rfc6749#section-5.1)):

```
Cache-Control: no-store
Pragma: no-cache
```

## Error Response

```json
{
  "error": "invalid_grant",
  "error_description": "The authorization code has expired."
}
```

| Error Code | Meaning |
|-----------|---------|
| `invalid_request` | Missing or malformed parameter |
| `invalid_client` | Client authentication failed |
| `invalid_grant` | Grant (code, token, credentials) is invalid or expired |
| `unauthorized_client` | Client is not authorized for this grant type |
| `unsupported_grant_type` | Server does not support the requested grant type |
| `invalid_scope` | Requested scope is invalid or exceeds what was granted |

## Security Best Practices

1. **Always use PKCE** — even for confidential clients. It prevents code interception attacks.
2. **Validate redirect URIs exactly** — no wildcards, no open redirects.
3. **Use short-lived access tokens** (5-15 minutes) with refresh tokens for longevity.
4. **Store client secrets securely** — environment variables or a secrets manager, never in code.
5. **Validate the `state` parameter** to prevent CSRF.
6. **Use `response_type=code`** — never `token` (implicit flow is deprecated).
7. **Register all redirect URIs** — reject requests with unregistered URIs.

## Relevant RFCs

- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 6750 — OAuth 2.0 Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [RFC 7636 — Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8628 — OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [RFC 7009 — OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
- [RFC 7662 — OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC 8414 — OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
