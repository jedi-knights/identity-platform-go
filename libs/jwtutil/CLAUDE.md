# libs/jwtutil — Claude Context

## Purpose

Single source of truth for JWT structure across the identity platform. Provides the canonical `Claims` type, `Sign`, `Parse`, and `NewClaims`. All services that issue or validate JWTs must use this package — never define a local claims struct.

---

## Claims Structure

```go
type Claims struct {
    jwt.RegisteredClaims
    ClientID    string   `json:"client_id"`
    Scope       string   `json:"scope"`            // RFC 9068 §2.2.3.1: space-delimited
    Roles       []string `json:"roles,omitempty"`
    Permissions []string `json:"permissions,omitempty"`
}
```

- **`Scope`** is a single space-delimited string, not a slice — this is per RFC 9068 §2.2.3.1. Split with `strings.Fields` when evaluating individual scopes.
- **`Roles` and `Permissions`** are `omitempty` — tokens issued without RBAC context omit these fields. Resource services must handle tokens where these claims are absent.

---

## NewClaims Config Struct

`NewClaims` takes a `ClaimsConfig` struct rather than positional parameters. This is intentional — nine string/time parameters in the same signature are easy to transpose silently. **Do not refactor this to positional arguments.**

`Roles` and `Permissions` slices are defensively copied inside `NewClaims`; callers may safely mutate their slices after the call.

---

## Signing Algorithm

All tokens are signed with **HMAC-SHA256** (`HS256`). RS256 via JWKS is on the roadmap (RFC 7517/7518) but not yet implemented. `Parse` enforces the expected algorithm — tokens with a different `alg` header return `ErrTokenInvalid`.

---

## Sentinel Errors

`Parse` returns one of three sentinels so callers can distinguish failure modes without importing the `golang-jwt/jwt` library directly:

| Sentinel | When returned |
|----------|---------------|
| `ErrTokenExpired` | Expiry time has passed |
| `ErrTokenMalformed` | Raw string is not a well-formed JWT |
| `ErrTokenInvalid` | Signature failure, algorithm mismatch, or any other validity error |

Use `errors.Is` to check these. Any error from `Parse` means the token is not valid for use.

---

## RFC 7662 Compliance is the Caller's Responsibility

`Parse` returns an error for invalid tokens. Converting that error to `{"active": false}` (instead of propagating it as a 4xx) is the caller's job, not this package's. The `token-introspection-service` is where that RFC 7662 compliance lives.
