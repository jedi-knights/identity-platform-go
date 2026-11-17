# identity-service — Claude Context

## What This Service Does

User identity store. Handles user registration and login. Verifies passwords and returns user identity — **it does not issue tokens**. Token issuance is auth-server's responsibility.

auth-server's `authorization_code` grant strategy calls this service via the `UserAuthenticator` port to verify end-user credentials before completing the authorization code flow.

---

## Password Handling

Passwords are bcrypt-hashed before storage. The `PasswordHasher` interface (Strategy pattern) decouples the hashing algorithm from the application layer:

```go
type PasswordHasher interface {
    Hash(password string) (string, error)
    Compare(hash, password string) error
}
```

`BcryptHasher` is the only implementation. The interface exists to keep `AuthService` testable with a mock hasher — not because algorithm swapping is planned.

**Do not store or log plain-text passwords.** The only place a plain-text password should appear is as input to `PasswordHasher.Hash` or `PasswordHasher.Compare`.

---

## Persistence Adapters

Two outbound adapters (same pattern as client-registry-service):

| Adapter | Package | Used when |
|---------|---------|-----------|
| In-memory | `adapters/outbound/memory` | `IDENTITY_DB_URL` unset |
| PostgreSQL | `adapters/outbound/postgres` | `IDENTITY_DB_URL` set |

---

## Email delivery

`IDENTITY_EMAIL_SENDER` selects the `domain.EmailSender`: `stdout` (default; logs the link), `noop`, or `smtp`. `smtp` delivers plain-text mail through a relay on a submission port using STARTTLS (implicit-TLS port 465 is not supported) and needs `IDENTITY_EMAIL_SMTP_HOST`, `IDENTITY_EMAIL_SMTP_PORT` (587), `IDENTITY_EMAIL_FROM`, and optionally `IDENTITY_EMAIL_SMTP_USERNAME`/`IDENTITY_EMAIL_SMTP_PASSWORD` (AUTH PLAIN, only sent over TLS). Incomplete smtp settings fail startup. The password is a secret: `fly secrets set`, never fly.toml. Recipient addresses are parsed and display names stripped of control characters, so request input cannot inject headers. Delivery errors name the SMTP stage only — never the body or credentials.

---

## Rate Limiting (password reset)

`POST /auth/request-password-reset` is limited **per submitted email** and `POST /auth/reset-password` **per client IP** (TCP peer; `X-Forwarded-For` is not trusted). Limits are in-memory and per replica, so the fleet ceiling is replicas × limit. The request limiter keys on the submitted address, never on account existence, so a 429 cannot be used to enumerate accounts. Tune with `IDENTITY_RATELIMIT_RESET_{REQUEST,REDEEM}_{MAX,WINDOW_SECS}`; a Max of `0` disables that limiter. Behind a proxy (login-ui) every caller shares the proxy's IP unless `IDENTITY_RATELIMIT_TRUSTED_PROXIES` (comma-separated CIDRs) lists the proxy's network: then the last `X-Forwarded-For` entry from those peers is the key. Never trust that header from other peers — it is client-controlled. login-ui sends it from the header named by `LOGIN_UI_SERVER_CLIENT_IP_HEADER` (Fly: `Fly-Client-IP`). Left unset, the redeem limit is a service-wide ceiling — raise it accordingly.

---

## What This Service Does NOT Do

- Does not issue JWTs or OAuth tokens — that is auth-server.
- Does not perform authorization — that is authorization-policy-service.
- Does not manage OAuth clients — that is client-registry-service.

`LoginResponse` returns a `UserID` string, not a token. The `authorization_code` grant in auth-server calls `VerifyCredentials` and receives that user ID, then proceeds to issue a token from its own token service.

---

## Relationship to auth-server

auth-server's `identityservice` outbound adapter calls `POST /auth/login` on this service. The `UserAuthenticator` port in auth-server abstracts this — when `AUTH_IDENTITY_SERVICE_URL` is unset, the adapter is nil and the `authorization_code` grant remains a stub.
