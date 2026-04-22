# API Keys

## Overview

An API key is a static, opaque string that a client includes in requests to identify itself to an API. API keys are primarily used for **identification and rate limiting**, not authentication in the security sense. They answer "which application is calling?" rather than "which user is calling?"

## How It Works

```
Client                                          Server
  │                                               │
  │─── GET /api/data ──────────────────────────▶ │
  │    X-API-Key: ak_live_7f3a2b...              │
  │                                               │
  │    ┌──────────────────────────────────┐       │
  │    │ Server looks up key in database  │       │
  │    │ → identifies client application  │       │
  │    │ → checks rate limits / quotas    │       │
  │    │ → applies access tier            │       │
  │    └──────────────────────────────────┘       │
  │                                               │
  │◀── 200 OK ───────────────────────────────── │
```

1. The API provider generates a key and issues it to the consumer (typically through a developer portal).
2. The consumer includes the key in every request.
3. The server validates the key, identifies the caller, and applies any associated policies.

## Common Transmission Methods

| Method | Example | Notes |
|--------|---------|-------|
| Custom header | `X-API-Key: ak_live_7f3a2b...` | Most common; keeps keys out of URLs and logs |
| Query parameter | `?api_key=ak_live_7f3a2b...` | Convenient but leaks in server logs, browser history, and referrer headers |
| `Authorization` header | `Authorization: ApiKey ak_live_7f3a2b...` | Less common; no standard scheme name |

## Key Design Best Practices

### Generation
- Use cryptographically random values (at least 32 bytes / 256 bits).
- Add a recognizable prefix for the key type: `ak_live_`, `ak_test_`, `sk_` (secret key).
- Store only a hash of the key server-side. Show the full key to the user exactly once at creation time.

### Management
- Support multiple keys per consumer for rotation without downtime.
- Provide revocation — revoking a key must take effect immediately, not at expiration.
- Set expiration dates and require periodic rotation.
- Scope keys to specific operations or resources when possible.

### Security
- Always transmit over TLS.
- Never embed keys in client-side code (mobile apps, SPAs, browser JavaScript).
- Monitor for anomalous usage patterns and support automatic suspension.

## Security Properties

| Property | Assessment |
|----------|-----------|
| Identifies caller | Yes — the application, not the user |
| Authenticates caller | Weakly — possession of the key is the only proof |
| Authorization granularity | Coarse — typically per-application, not per-user |
| Expiration | Only if enforced server-side |
| Revocability | Yes, if the server supports it |
| Replay protection | None — the same key works until revoked |

## API Keys vs. Authentication Tokens

| Aspect | API Key | OAuth2 Access Token |
|--------|---------|-------------------|
| Represents | An application | A user + application + scope |
| Lifetime | Long-lived (months/years) | Short-lived (minutes/hours) |
| Scope | Coarse | Fine-grained per-token |
| Revocation | Manual | Automatic (expiration) + manual |
| Delegation | No | Yes — user delegates to app |

## When to Use

- Public APIs where you need to identify callers and enforce rate limits.
- Server-to-server communication where both sides are trusted.
- Metering and billing — tracking usage per consumer.
- Low-sensitivity endpoints that do not expose user data.

## When Not to Use

- User-facing authentication — API keys cannot represent "which user" without additional context.
- Applications that need fine-grained, per-user authorization.
- Anywhere keys would be exposed client-side (browser, mobile app bundles).
- High-security operations that require proof of user identity.

## Common Pitfalls

1. **Treating API keys as authentication.** An API key proves which app is calling, not which user. Combine with OAuth2 or session auth for user identity.
2. **Storing keys in plaintext.** Store a SHA-256 hash server-side. If the database leaks, plaintext keys give immediate access.
3. **Embedding keys in version control.** Use environment variables or a secrets manager. Scan repositories with tools like GitGuardian or truffleHog.
4. **No rotation mechanism.** If a key is compromised and cannot be rotated without downtime, the blast radius is unlimited.
