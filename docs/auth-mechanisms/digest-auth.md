# HTTP Digest Authentication

## Overview

Digest Authentication is a challenge-response scheme that improves on Basic Auth by never sending the password in cleartext. Instead, the client proves knowledge of the password by hashing it with a server-provided nonce. It is defined in [RFC 7616](https://datatracker.ietf.org/doc/html/rfc7616).

## How It Works

```
Client                                               Server
  │                                                    │
  │─── GET /resource ────────────────────────────────▶│
  │                                                    │
  │◀── 401 Unauthorized ────────────────────────────  │
  │    WWW-Authenticate: Digest                        │
  │      realm="example",                              │
  │      nonce="dcd98b...",                            │
  │      qop="auth",                                   │
  │      algorithm=SHA-256                             │
  │                                                    │
  │─── GET /resource ────────────────────────────────▶│
  │    Authorization: Digest                           │
  │      username="john",                              │
  │      realm="example",                              │
  │      nonce="dcd98b...",                            │
  │      uri="/resource",                              │
  │      response="6629fa...",                         │
  │      qop=auth,                                     │
  │      nc=00000001,                                  │
  │      cnonce="0a4f11..."                            │
  │                                                    │
  │◀── 200 OK ──────────────────────────────────────  │
```

1. The client requests a protected resource.
2. The server responds with a `401` containing a `nonce` (a one-time value), the `realm`, and a quality-of-protection directive (`qop`).
3. The client computes a hash digest:
   - `HA1 = H(username:realm:password)`
   - `HA2 = H(method:uri)`
   - `response = H(HA1:nonce:nc:cnonce:qop:HA2)`
4. The client sends the `response` hash. The server performs the same computation with the stored password (or stored `HA1`) and compares.

## Security Properties

| Property | Assessment |
|----------|-----------|
| Confidentiality | Partial — password is never sent, but metadata is cleartext |
| Replay protection | Yes — nonce and nonce-count (`nc`) prevent simple replays |
| Credential exposure | Lower than Basic — password hash is sent, not the password |
| Man-in-the-middle | Vulnerable without TLS — an attacker can downgrade to Basic |

## Advantages Over Basic Auth

- The password is never transmitted, even in encoded form.
- The nonce prevents replay attacks (the same response hash cannot be reused).
- The `cnonce` (client nonce) provides mutual authentication and protects against chosen-plaintext attacks.

## Limitations

- The server must store the password in a recoverable form (plaintext or `HA1` hash), which is less secure than storing a bcrypt/argon2 hash.
- Vulnerable to man-in-the-middle attacks that strip the `Digest` challenge and substitute `Basic`.
- More complex to implement than Basic Auth with minimal practical gain when TLS is already in use.
- No support for modern features like token expiration, scopes, or delegation.

## When to Use

- Legacy systems that cannot use TLS and need better-than-Basic protection.
- Environments where password hashing on every request is acceptable.

## When Not to Use

- Modern applications — TLS + Bearer tokens provides strictly better security with less complexity.
- Systems that store passwords with modern one-way hashes (bcrypt, scrypt, argon2), since Digest Auth requires the server to reconstruct `HA1`.

## Practical Status

Digest Authentication is rarely used in modern systems. TLS made its primary advantage (avoiding cleartext passwords) unnecessary, while its requirement for recoverable passwords makes it actively worse than Basic Auth + TLS from a credential storage perspective. Most modern APIs use Bearer tokens (OAuth2/JWT) instead.

## Relevant RFCs

- [RFC 7616 — HTTP Digest Access Authentication](https://datatracker.ietf.org/doc/html/rfc7616)
- [RFC 7235 — Hypertext Transfer Protocol: Authentication](https://datatracker.ietf.org/doc/html/rfc7235)
