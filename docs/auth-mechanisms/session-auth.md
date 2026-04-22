# Session-Based Authentication

## Overview

Session-based authentication is the traditional web authentication model. The user submits credentials once, the server creates a session and returns a session ID in a cookie, and the browser automatically includes that cookie on subsequent requests. The server maintains session state and uses the session ID to look up the authenticated user.

## How It Works

```
Browser                                         Server
  │                                               │
  │─── POST /login ──────────────────────────── ▶│
  │    { "username": "john", "password": "..." }  │
  │                                               │
  │    ┌─────────────────────────────────────┐    │
  │    │ Validate credentials                │    │
  │    │ Create session in store (memory,    │    │
  │    │   Redis, database)                  │    │
  │    │ session_id = random_token()         │    │
  │    │ store[session_id] = { user, roles } │    │
  │    └─────────────────────────────────────┘    │
  │                                               │
  │◀── 200 OK ──────────────────────────────────│
  │    Set-Cookie: sid=abc123; HttpOnly;          │
  │      Secure; SameSite=Lax; Path=/            │
  │                                               │
  │─── GET /dashboard ─────────────────────────▶│
  │    Cookie: sid=abc123                         │
  │                                               │
  │    ┌─────────────────────────────────────┐    │
  │    │ Look up session_id in store         │    │
  │    │ → found: user=john, roles=[admin]   │    │
  │    └─────────────────────────────────────┘    │
  │                                               │
  │◀── 200 OK (dashboard content) ──────────────│
```

1. The user submits credentials (typically via an HTML form or JSON payload).
2. The server validates the credentials against a user store.
3. The server creates a session record, generates a random session ID, and stores the mapping.
4. The session ID is returned to the browser in a `Set-Cookie` header.
5. The browser automatically attaches the cookie to every subsequent request to the same origin.
6. The server looks up the session ID on each request to identify the user.

## Session Storage Options

| Store | Pros | Cons |
|-------|------|------|
| In-memory (process) | Simplest, fastest | Lost on restart, cannot scale horizontally |
| Redis / Memcached | Fast, shared across instances, built-in TTL | Additional infrastructure dependency |
| Database (SQL) | Durable, queryable (e.g., "show all active sessions") | Slower, requires cleanup of expired sessions |
| Signed cookies | No server-side store needed | Limited size (~4 KB), session data visible to client |

## Cookie Security Attributes

| Attribute | Purpose |
|-----------|---------|
| `HttpOnly` | Prevents JavaScript from reading the cookie — mitigates XSS-based session theft |
| `Secure` | Cookie is only sent over HTTPS |
| `SameSite=Lax` or `Strict` | Prevents the cookie from being sent on cross-site requests — mitigates CSRF |
| `Path=/` | Cookie applies to the entire domain |
| `Max-Age` / `Expires` | Controls cookie lifetime in the browser |

## Session Lifecycle

```
Create ──▶ Active ──▶ Expired/Invalidated ──▶ Deleted
              │
              ├── idle timeout (e.g., 30 minutes of inactivity)
              ├── absolute timeout (e.g., 8 hours regardless of activity)
              └── explicit logout (user or admin action)
```

- **Idle timeout**: session expires after N minutes without a request.
- **Absolute timeout**: session expires after N hours regardless of activity.
- **Logout**: the server deletes the session record and instructs the browser to clear the cookie.

## Security Properties

| Property | Assessment |
|----------|-----------|
| Credential exposure | Low — credentials sent only at login |
| Session hijacking | Possible if session ID is intercepted (mitigated by `Secure`, `HttpOnly`) |
| CSRF | Possible — mitigated by `SameSite` cookies and CSRF tokens |
| Scalability | Requires shared session store for multi-instance deployments |
| Revocation | Immediate — delete the session from the store |

## CSRF Protection

Because browsers automatically attach cookies, a malicious site can trigger requests to your application on behalf of the logged-in user. Defenses:

1. **SameSite cookies** (`Lax` or `Strict`) — the browser will not send the cookie on cross-origin requests.
2. **Synchronizer token pattern** — embed a random token in forms and validate it server-side.
3. **Double-submit cookie** — set a CSRF token in a cookie and require the client to echo it in a header.

## Sessions vs. Tokens

| Aspect | Session-Based | Token-Based (JWT) |
|--------|--------------|-------------------|
| State | Server-side (stateful) | Client-side (stateless) |
| Storage | Server session store | Client (cookie, localStorage, memory) |
| Scalability | Requires shared store | Scales horizontally without shared state |
| Revocation | Immediate (delete session) | Difficult (must wait for expiration or use a blocklist) |
| Cross-domain | Difficult (cookies are origin-bound) | Easy (tokens can be sent to any origin) |
| Best for | Traditional web apps, server-rendered pages | APIs, SPAs, mobile apps, microservices |

## When to Use

- Server-rendered web applications (HTML pages, form submissions).
- Applications where immediate session revocation is important (e.g., "log out all devices").
- Internal tools behind a single domain.

## When Not to Use

- APIs consumed by mobile apps, SPAs, or third-party clients — tokens are more practical.
- Microservice architectures — session state creates coupling between services.
- Cross-domain scenarios — cookies do not flow across origins without complex CORS configuration.
