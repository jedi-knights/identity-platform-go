# HTTP Basic Authentication

## Overview

HTTP Basic Authentication is the simplest authentication scheme defined in the HTTP standard. The client sends the user's credentials (username and password) with every request, encoded in the `Authorization` header. It is defined in [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617).

## How It Works

```
Client                                          Server
  │                                               │
  │─── GET /resource ───────────────────────────▶│
  │                                               │
  │◀── 401 Unauthorized ─────────────────────────│
  │    WWW-Authenticate: Basic realm="example"    │
  │                                               │
  │─── GET /resource ───────────────────────────▶│
  │    Authorization: Basic dXNlcjpwYXNz          │
  │                                               │
  │◀── 200 OK ───────────────────────────────────│
```

1. The client makes a request without credentials.
2. The server responds with `401 Unauthorized` and a `WWW-Authenticate: Basic` challenge.
3. The client retransmits the request with an `Authorization` header containing `Basic <base64(username:password)>`.
4. The server decodes the header, validates the credentials, and returns the resource.

## Header Format

```
Authorization: Basic base64(username ":" password)
```

The value is **Base64-encoded, not encrypted**. Anyone who intercepts the header can trivially decode it.

## Example

```http
GET /api/users HTTP/1.1
Host: api.example.com
Authorization: Basic am9objpzZWNyZXQ=
```

Decoding `am9objpzZWNyZXQ=` yields `john:secret`.

## Security Properties

| Property | Assessment |
|----------|-----------|
| Confidentiality | None — credentials are Base64-encoded, not encrypted |
| Replay protection | None — same header works for every request |
| Credential exposure | High — password sent on every request |
| Brute-force resistance | None built in — requires server-side rate limiting |

## When to Use

- Internal services behind a VPN or private network
- Quick prototyping or development environments
- Machine-to-machine calls where TLS is guaranteed and credential rotation is straightforward

## When Not to Use

- Public-facing APIs exposed to the internet without TLS
- Applications where users manage their own credentials interactively
- Any scenario requiring fine-grained authorization, token expiration, or delegation

## Mitigations

- **Always use TLS.** Basic Auth over plain HTTP exposes credentials to anyone on the network.
- Implement rate limiting and account lockout to resist brute-force attacks.
- Use strong, randomly generated passwords rather than user-chosen ones.
- Consider upgrading to token-based authentication (Bearer/JWT) for production systems.

## Relevant RFCs

- [RFC 7617 — The 'Basic' HTTP Authentication Scheme](https://datatracker.ietf.org/doc/html/rfc7617)
- [RFC 7235 — Hypertext Transfer Protocol: Authentication](https://datatracker.ietf.org/doc/html/rfc7235)
