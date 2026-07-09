# client-registry-service — Claude Context

## What This Service Does

OAuth client registry. Manages the lifecycle of OAuth clients (create, read, list, delete, validate). auth-server's `ClientAuthenticator` adapter calls this service's `POST /clients/validate` endpoint to authenticate clients at token issuance time.

---

## Secret Handling — Critical Invariant

Client secrets are **bcrypt-hashed before storage**. The plain-text secret is returned exactly once in the `CreateClient` response and is never stored or recoverable.

```
CreateClient → generate random hex → bcrypt hash → store hash → return plain text once
ValidateClient → bcrypt.CompareHashAndPassword(stored hash, presented secret)
```

**Do not change `ValidateClient` to use `==` or `strings.EqualFold`** — bcrypt comparison is constant-time and prevents timing attacks. The hash stored in the repository is never the raw secret.

---

## Persistence Adapters

This service has two outbound adapters — unlike most services which only have in-memory:

| Adapter | Package | Used when |
|---------|---------|-----------|
| In-memory | `adapters/outbound/memory` | `CLIENT_DB_URL` unset (default / development) |
| PostgreSQL | `adapters/outbound/postgres` | `CLIENT_DB_URL` set |

The swap happens in `container.go`. Both implement `domain.ClientRepository`. The compile-time interface check (`var _ domain.ClientRepository = (*Repository)(nil)`) on each adapter marks the swap point.

---

## Validation Rules

- `Name` is required; empty name returns `ErrCodeBadRequest`.
- At least one `GrantType` is required; empty list returns `ErrCodeBadRequest`.
- `Scopes` and `RedirectURIs` may be empty (valid for `client_credentials`-only clients).
- `Active` flag: inactive clients fail `ValidateClient` even with correct credentials.

---

## JWT-Bearer Client Authentication (ADR-0023)

`OAuthClient.JWKSURI` (RFC 7591 §2 registration metadata) is optional on both `POST /clients` and `POST /register` (`jwks_uri` field). Set means the client can authenticate at auth-server's token endpoint with a signed JWT instead of `client_secret` (RFC 7523); empty means `client_secret` remains its only credential. `GetClient`/`ListClients` echo it back so auth-server's `clientregistry` adapter can resolve it via `Lookup`.

Only `jwks_uri` (a URL) is supported — not an embedded `jwks` document. The RFC 7592 update endpoint does not currently change `jwks_uri` once set on a client; it is create-time only in this reference implementation.

---

## Relationship to auth-server

auth-server's `clientregistry` outbound adapter calls this service over HTTP. The auth-server `ClientAuthenticator` port abstracts this so the in-memory fallback (used when `AUTH_CLIENT_REGISTRY_URL` is unset) runs locally without the full stack.
