# token-introspection-service — Claude Context

## What This Service Does

Implements RFC 7662 token introspection. Validates JWT signatures and optionally checks a Redis-backed revocation store. Called by example-resource-service (and any other resource server) to validate Bearer tokens on every request.

---

## RFC 7662 Invariant — Never Break This

**Introspection always returns HTTP 200**, even for invalid, expired, or revoked tokens. An invalid token must return `{"active": false}`, never a `4xx`. This is required by RFC 7662 §2.2.

The HTTP handler must never propagate a validation error as a `400` or `401`. Errors from `IntrospectionService.Introspect` represent internal failures, not client errors — they should return `500` or `{"active": false}` depending on the failure mode.

---

## Revocation Check

The revocation check is optional — it only runs when a Redis URL is configured via `INTROSPECTION_REDIS_URL`.

How it works:
- auth-server stores a key in Redis when a token is issued and **deletes** it when the token is revoked.
- `RevocationChecker.IsActive` checks for key presence: present = active, missing = revoked.
- **Infrastructure errors fail closed**: if Redis is unavailable, the token is treated as inactive (`{active: false}`). Security takes precedence over availability.

When Redis is not configured, token revocation is not enforced — a revoked token will appear active here until its JWT expiry. This is acceptable for local development; it must not be the configuration in any environment where revocation matters.

---

## Validation Pipeline

```
raw JWT → jwt validator (signature + expiry) → revocation check (if Redis configured) → IntrospectionResult
```

`IntrospectionService` orchestrates this pipeline. It calls `domain.TokenValidator` first — if the JWT is already invalid or expired, the revocation check is skipped.

---

## Adapters

| Adapter | Interface | Used when |
|---------|-----------|-----------|
| `adapters/outbound/jwt.Validator` | `domain.TokenValidator` | Always — validates JWT signature using `libs/jwtutil` |
| `adapters/outbound/redis.RevocationStore` | `domain.RevocationChecker` | `INTROSPECTION_REDIS_URL` set |

When Redis is unset, `container.go` wires `nil` for the revocation checker. `IntrospectionService` handles `nil` safely — the revocation step is skipped.
