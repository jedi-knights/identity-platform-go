# Bearer Tokens & JSON Web Tokens (JWT)

## Overview

A **bearer token** is an opaque or structured credential that grants access to whoever possesses it — "the bearer." The most common format for bearer tokens is the **JSON Web Token (JWT)**, a compact, URL-safe, self-contained token that carries claims about the subject.

Bearer token usage is defined in [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750). JWT is defined in [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519). The JWT profile for OAuth 2.0 access tokens is defined in [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068).

## Bearer Tokens

### How They Work

```
Client                                          Server
  │                                               │
  │─── GET /api/resource ───────────────────────▶│
  │    Authorization: Bearer eyJhbGciOi...        │
  │                                               │
  │    ┌──────────────────────────────────┐       │
  │    │ Extract token from header        │       │
  │    │ Validate (signature, expiry,     │       │
  │    │   issuer, audience)              │       │
  │    │ Extract claims (sub, scope, etc) │       │
  │    │ Enforce authorization            │       │
  │    └──────────────────────────────────┘       │
  │                                               │
  │◀── 200 OK ──────────────────────────────────│
```

The token is sent in the `Authorization` header:

```
Authorization: Bearer <token>
```

The server validates the token and uses the embedded claims (or looks up the token in a store) to authorize the request.

### Error Responses (RFC 6750)

When a bearer token is missing, invalid, or has insufficient scope, the server responds with a `WWW-Authenticate` header:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="example",
  error="invalid_token",
  error_description="The token has expired"
```

| Error | HTTP Status | Meaning |
|-------|-------------|---------|
| (no error, no token) | 401 | No token was provided |
| `invalid_token` | 401 | Token is malformed, expired, or revoked |
| `insufficient_scope` | 403 | Token is valid but lacks required scopes |

## JSON Web Tokens (JWT)

### Structure

A JWT consists of three Base64URL-encoded parts separated by dots:

```
header.payload.signature
```

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE3MTYyMzkwMjJ9.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

#### Header

Describes the token type and signing algorithm:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

#### Payload (Claims)

Contains statements about the subject and metadata:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": "https://api.example.com",
  "exp": 1716242622,
  "iat": 1716239022,
  "scope": "read write",
  "client_id": "my-app"
}
```

#### Registered Claims

| Claim | Name | Purpose |
|-------|------|---------|
| `iss` | Issuer | Who issued the token |
| `sub` | Subject | Who the token is about |
| `aud` | Audience | Who the token is intended for |
| `exp` | Expiration | Unix timestamp after which the token is invalid |
| `nbf` | Not Before | Unix timestamp before which the token is not valid |
| `iat` | Issued At | Unix timestamp when the token was created |
| `jti` | JWT ID | Unique identifier for the token (used for revocation) |

#### Signature

The signature verifies that the token has not been tampered with:

```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

### Signing Algorithms

| Algorithm | Type | Key | Use Case |
|-----------|------|-----|----------|
| `HS256` | Symmetric (HMAC) | Shared secret | Single service that issues and validates |
| `RS256` | Asymmetric (RSA) | Private key signs, public key verifies | Distributed systems — anyone can verify without the signing key |
| `ES256` | Asymmetric (ECDSA) | Private key signs, public key verifies | Same as RS256 but smaller keys and signatures |

Asymmetric algorithms (RS256, ES256) are preferred in distributed systems because resource servers can verify tokens using the public key without ever possessing the signing key.

### Validation Checklist

When a server receives a JWT, it must:

1. Decode the header and verify the `alg` is expected (prevent algorithm confusion attacks).
2. Verify the signature using the appropriate key.
3. Check `exp` — reject if the token has expired.
4. Check `nbf` — reject if the token is not yet valid.
5. Check `iss` — reject if the issuer is not trusted.
6. Check `aud` — reject if this server is not the intended audience.
7. Extract `scope` or `permissions` and enforce authorization.

## Security Properties

| Property | Assessment |
|----------|-----------|
| Self-contained | Yes — claims are embedded in the token |
| Tamper-proof | Yes — signature detects modification |
| Confidential | No — payload is Base64-encoded, not encrypted (use JWE for encryption) |
| Revocation | Difficult — the token is valid until it expires unless a blocklist is maintained |
| Stateless | Yes — no server-side lookup required for validation |

## Common Pitfalls

1. **Storing JWTs in localStorage.** Vulnerable to XSS. Use `HttpOnly` cookies or keep tokens in memory.
2. **Not validating the `alg` header.** An attacker can set `alg: "none"` to bypass signature verification. Always enforce the expected algorithm.
3. **Long expiration times.** A stolen JWT is valid until it expires. Keep access token lifetimes short (5-15 minutes).
4. **Putting sensitive data in the payload.** JWT payloads are not encrypted — anyone can decode them. Use JWE if confidentiality is needed.
5. **Using JWTs for sessions.** JWTs cannot be revoked without server-side state, which eliminates their stateless advantage. Use sessions for revocable authentication.

## Relevant RFCs

- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 6750 — OAuth 2.0 Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [RFC 9068 — JSON Web Token Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)
- [RFC 7515 — JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 7516 — JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516)
- [RFC 7518 — JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
