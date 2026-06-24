# ADR-0013: Dynamic Client Registration (RFC 7591 + RFC 7592)

**Status**: Accepted
**Date**: 2026-06-23

## Context

Every OAuth client today is registered by hand. An operator hits `POST /clients` on `client-registry-service` with a `CreateClientRequest`, copies the returned `client_id` and `client_secret`, and pastes them into whatever app needs to integrate. That model holds for first-party services (`auth-server` calling `client-registry-service`, the seeded `test-client` for development), but it breaks the moment a third-party MCP connector, a self-hosted web app, or any client built outside the operator's reach wants to integrate. The user experience is: read a paragraph of docs, find an admin, file a ticket, wait.

[RFC 7591 Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591) defines the canonical alternative: a public-ish `POST /register` endpoint where any client can submit metadata and receive credentials in a single round trip. Every MCP connector and every modern OAuth client library expects this. The MCP authorization specification in particular treats Dynamic Client Registration as a recommended capability — without it, every new connector requires manual provisioning.

The existing `POST /clients` endpoint on `client-registry-service` is close to RFC 7591 in shape but differs in details:

- Field names: RFC 7591 uses `redirect_uris` (we have it), `grant_types` (we have it), `client_name` (we use `name`), `scope` (single space-delimited string; we use `scopes` as a JSON array), `token_endpoint_auth_method` (not modeled), `client_type` (not modeled — but ADR-0009 adds it).
- Response: RFC 7591 mandates `client_id_issued_at`, optionally `client_secret_expires_at`, and (for the management protocol RFC 7592) `registration_access_token` and `registration_client_uri`.
- Status code: RFC 7591 requires `201 Created`; the existing handler returns `200 OK`.
- Error shape: RFC 7591 has its own error codes (`invalid_redirect_uri`, `invalid_client_metadata`, `invalid_software_statement`) — distinct from `apperrors.ErrCodeBadRequest`.

Three additional questions drive the design:

1. **Open or gated?** RFC 7591 §3 allows the server to require an `initial_access_token` from the request. Fully open lets anyone register; gated trades open access for spam resistance.
2. **Default `token_endpoint_auth_method`?** Public clients (no secret, PKCE only) and confidential clients (secret + PKCE) have different defaults. MCP and SPAs want public.
3. **Implement RFC 7592 management endpoints too?** The companion spec defines `GET/PUT/DELETE /register/<client_id>` for self-service updates. Adds complexity but enables clients to rotate their own metadata without an admin.

## Decision

Add **RFC 7591 dynamic client registration** to `client-registry-service` at `POST /register` and **RFC 7592 client configuration endpoints** at `GET/PUT/DELETE /register/{client_id}`. The existing `POST /clients` route remains as a first-party admin endpoint, distinct from the RFC 7591 surface; the two endpoints share storage but not request/response shapes or auth model. Registration is **open by default** (no initial access token required) with rate limiting and an optional `BotDefender` hook (consistent with ADR-0011's login surface). Default `token_endpoint_auth_method` is **`none`** — public client, PKCE-protected — so MCP connectors and SPAs work without secret handling.

### Endpoint surface

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/register` | `POST` | none (or `Bearer <initial_access_token>` when gating is enabled) | Create a new client (RFC 7591 §3) |
| `/register/{client_id}` | `GET` | `Bearer <registration_access_token>` | Read the registered client's metadata (RFC 7592 §2.1) |
| `/register/{client_id}` | `PUT` | `Bearer <registration_access_token>` | Update the registered client's metadata (RFC 7592 §2.2) |
| `/register/{client_id}` | `DELETE` | `Bearer <registration_access_token>` | Deregister the client (RFC 7592 §2.3) |
| `/clients` | `POST` | first-party operator (existing) | Unchanged admin endpoint — different field set, no registration access token |

The `/clients` endpoint stays for two reasons: first-party callers (`auth-server`'s seed flow, internal admin tooling) keep working without rewrite; and operator-driven client creation belongs in a different trust model from public self-registration. They sit side by side in the same service.

### Request shape (RFC 7591 §2)

```json
POST /register
Content-Type: application/json

{
  "client_name":                "MCP Filesystem Connector",
  "redirect_uris":              ["https://connector.example.com/callback"],
  "grant_types":                ["authorization_code", "refresh_token"],
  "response_types":             ["code"],
  "token_endpoint_auth_method": "none",
  "scope":                      "openid email profile",
  "contacts":                   ["security@example.com"],
  "client_uri":                 "https://connector.example.com",
  "logo_uri":                   "https://connector.example.com/logo.png",
  "tos_uri":                    "https://connector.example.com/tos",
  "policy_uri":                 "https://connector.example.com/privacy"
}
```

All fields are optional except as documented under "Validation rules" below. RFC 7591 fields not modeled in the existing `OAuthClient` struct (`token_endpoint_auth_method`, `response_types`, `contacts`, `client_uri`, `logo_uri`, `tos_uri`, `policy_uri`, `software_id`, `software_version`, `software_statement`) are added to the domain type:

```go
type OAuthClient struct {
    ID           string
    Secret       string   // empty for public clients
    Name         string   // RFC 7591 client_name
    ClientType   ClientType // public | confidential (ADR-0009)
    TokenEndpointAuthMethod string // "client_secret_basic" | "client_secret_post" | "none"
    Scopes       []string
    RedirectURIs []string
    GrantTypes   []string
    ResponseTypes []string
    Contacts     []string
    ClientURI    string
    LogoURI      string
    TosURI       string
    PolicyURI    string
    SoftwareID   string  // RFC 7591 §2 — opaque identifier from the client author
    SoftwareVersion string
    RegistrationAccessTokenHash string  // bcrypt hash; never the raw token
    CreatedAt    time.Time
    UpdatedAt    time.Time
    Active       bool
}
```

`logo_uri`, `tos_uri`, `policy_uri` are the same fields ADR-0011's branding lookup reads — once this ADR lands, dynamically-registered clients automatically get per-RP branding in the login UI.

`software_statement` (RFC 7591 §2.3 — a JWT containing pre-signed client metadata) is **not implemented**. Verifying a software statement requires either a trust anchor list or a federation broker; both are out of scope for the reference implementation. A request that includes `software_statement` returns `invalid_software_statement`.

### Response shape

```json
HTTP/1.1 201 Created
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "client_id":                  "abc123…",
  "client_id_issued_at":        1750000000,
  "client_secret":              "<32-byte hex>",        // omitted when token_endpoint_auth_method = "none"
  "client_secret_expires_at":   0,                       // 0 = never expires
  "registration_access_token":  "<32-byte hex>",        // RFC 7592 §3
  "registration_client_uri":    "https://identity.example.com/register/abc123…",
  "client_name":                "MCP Filesystem Connector",
  "redirect_uris":              ["https://connector.example.com/callback"],
  "grant_types":                ["authorization_code", "refresh_token"],
  "response_types":             ["code"],
  "token_endpoint_auth_method": "none",
  "scope":                      "openid email profile"
}
```

The `registration_access_token` is the **only** credential that can read or modify the registration record via RFC 7592 endpoints. It is generated with `crypto/rand`, bcrypt-hashed before storage (same convention as `client_secret` per the existing `CLAUDE.md`), returned to the caller exactly once, and never recoverable. Loss means the client must be re-registered.

Public clients (`token_endpoint_auth_method = "none"`) get no `client_secret` field at all — RFC 7591 §3.2.1 is explicit that the field should be omitted, not emitted as an empty string.

### Validation rules

| Field | Rule | Error on failure |
|---|---|---|
| `redirect_uris` | Required for `authorization_code` grant. Each URI: scheme `https` (or `http://localhost` / `http://127.0.0.1` in dev), no fragment, no wildcard, byte-canonical. | `invalid_redirect_uri` |
| `grant_types` | Each value must be in `["authorization_code", "refresh_token", "client_credentials"]`. Default: `["authorization_code"]`. | `invalid_client_metadata` |
| `response_types` | Each value must be in `["code"]`. Default: `["code"]`. | `invalid_client_metadata` |
| `token_endpoint_auth_method` | One of `["none", "client_secret_basic", "client_secret_post"]`. Default: `"none"`. If `"none"`, `client_type` is forced to `public` and no secret is issued. | `invalid_client_metadata` |
| `scope` | Each scope must be in the platform's `scopes_supported` (ADR-0012). Default: `""` (the client gets no scopes — all subsequent token requests must request them explicitly via consent, and consent will fail). | `invalid_client_metadata` |
| `client_name` | Bounded length (≤ 200 chars). Defaults to `"Client " + first 8 chars of client_id`. | `invalid_client_metadata` |
| `logo_uri`, `tos_uri`, `policy_uri`, `client_uri` | Must be `https://` (or `http://localhost` in dev). | `invalid_client_metadata` |
| `contacts` | List of email-shaped strings (RFC 5322 minimal validation). Bounded length (≤ 10 entries). | `invalid_client_metadata` |
| `software_statement` | **Always rejected.** | `invalid_software_statement` |

Grant-type / response-type consistency check: if `grant_types` contains `authorization_code`, `response_types` must contain `code`. A request with `["authorization_code"]` grants but no `response_types` (which defaults to `["code"]`) is fine; a request that explicitly sets `response_types: []` and `grant_types: ["authorization_code"]` is `invalid_client_metadata`.

### Error response shape (RFC 7591 §3.2.2)

```json
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "invalid_redirect_uri",
  "error_description": "redirect_uris[0] must use https scheme"
}
```

The error codes are a closed set: `invalid_redirect_uri`, `invalid_client_metadata`, `invalid_software_statement`. Internal errors map to `500 Internal Server Error` with `error: "server_error"`. Distinct from `apperrors.ErrCode*` — the existing error response shape (RFC 7591 demands a specific JSON layout) does not pass through `apperrors`; the registration handler writes its own error response.

### Initial access token (optional gating)

When `CLIENT_REGISTRY_INITIAL_ACCESS_TOKEN` is set, `POST /register` requires `Authorization: Bearer <token>` and rejects the request with `401 invalid_token` otherwise. The check is constant-time bcrypt comparison against the stored hash. When the env var is **unset**, registration is open.

This is the single knob that lets an operator say "I trust the public internet to call this endpoint" or "I trust only my onboarding pipeline." Both modes use the same code path; the gate is a middleware. Defaulting to open matches the reference-implementation framing — a fresh `docker compose up` lets any developer register a client without configuring a token first.

### Rate limiting and bot defence

Even open registration must defend against abuse. The same `fixedWindowLimiter` pattern used in `auth-server`'s token handler applies:

| Endpoint | Limit | Key |
|---|---|---|
| `POST /register` | 5 per minute, 30 per hour | source IP |
| `GET/PUT/DELETE /register/{id}` | 30 per minute | `(source IP, client_id)` |

A `BotDefender` port (same shape as ADR-0011's hook) returns `Pass / Challenge / Block` per request. The default implementation passes everything; a CAPTCHA-backed implementation can be wired without touching the handler. Production deployments are expected to wire one; the reference implementation does not include CAPTCHA code.

### RFC 7592 management endpoints

Reading and modifying a registered client uses the `registration_access_token` returned at registration time. The token is bound to one `client_id` — presenting a valid token for client A while requesting client B's metadata returns `404 Not Found` (not `403`, which would confirm B exists).

`PUT /register/{client_id}` replaces the entire metadata record, RFC 7592 §2.2.1 style — not a partial update. Fields the client wants to keep must be re-submitted. This avoids the field-merging edge cases of `PATCH` and matches the spec's wording ("the client SHOULD send a complete representation"). Validation rules above re-apply.

`DELETE /register/{client_id}` is permanent. Tokens already issued to the client continue to validate until they expire — deregistration does not revoke outstanding tokens. A future ADR could couple deregistration to bulk revocation; this ADR does not.

### Compile-time interface checks

```go
var _ ports.RegistrationHandler = (*RegistrationHandler)(nil)
var _ ports.BotDefender = (*PassThroughBotDefender)(nil)
```

### Wiring into the rest of the platform

Three small changes elsewhere:

1. **`AUTH_REGISTRATION_ENDPOINT` env var** (defined in ADR-0012) gets set to the public URL of `POST /register`. `auth-server`'s metadata handler then emits the `registration_endpoint` field in `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration`. MCP and OIDC client libraries discover and use it automatically.
2. **`login-ui`'s branding lookup** (ADR-0011) already calls `GET /clients/{id}/display`, which projects the new `LogoURI`, `TosURI`, `PolicyURI` fields. The endpoint is **public** (unauthenticated) — it returns only fields that are intentionally shown on a consent screen any client could read by initiating an OAuth flow. No bearer token, no service secret. Rate-limited per IP (30/min) to bound enumeration. No login-ui change is required.
3. **The seeded `test-client`** (`AUTH_DEV_CLIENT_SECRET`) stays as it is — registered via the admin `POST /clients` route, not via `POST /register`. The two paths share storage, and the seeded client's `RegistrationAccessTokenHash` is empty, which is interpreted as "RFC 7592 endpoints are not available for this client" (any GET/PUT/DELETE returns `401`).

### Configuration surface

| Variable | Default | Purpose |
|---|---|---|
| `CLIENT_INITIAL_ACCESS_TOKEN` | unset → open | When set, `POST /register` requires `Authorization: Bearer <token>` |
| `CLIENT_REGISTRATION_BASE_URL` | (required for prod) | Public origin used to build `registration_client_uri` in responses |
| `CLIENT_BOT_DEFENDER` | `passthrough` | Strategy key — `passthrough` (default) or future implementations like `recaptcha` |

The `CLIENT_` prefix matches the existing convention in `client-registry-service` (`CLIENT_SERVER_HOST`, `CLIENT_SERVER_PORT`, `CLIENT_DB_URL`). Auth-server's deployment also sets `AUTH_REGISTRATION_ENDPOINT` (ADR-0012) to the public URL of `POST /register` so the metadata document advertises it.

## Consequences

**Positive**

- MCP connectors, OIDC RPs, and self-hosted web apps can self-onboard. The integration story shrinks from "ask an admin" to "POST to `/register`, save the credentials."
- RFC 7592 lets clients rotate their own metadata — change a redirect URI, update a logo, deregister — without operator involvement.
- The metadata field set (`logo_uri`, `tos_uri`, `policy_uri`, `contacts`) feeds the existing branding and operational-notification paths. `login-ui` automatically gets richer per-RP branding once dynamic registration starts being used.
- The `/register` and `/clients` routes co-exist, so the existing admin / seeded-client paths keep working unchanged. No migration of existing clients is required.
- Defaulting to public clients (`token_endpoint_auth_method = "none"`) matches the dominant use case (MCP + SPAs) and makes "register and immediately use" the path of least resistance.

**Negative / Trade-offs**

- A public-by-default registration endpoint is an obvious abuse target. The rate limit + bot-defender hook is the answer; the hook's default is pass-through. A production deployment without a real `BotDefender` is one motivated attacker away from a full client table. The trade is calling that out loudly here and in the README rather than baking in a CAPTCHA dependency.
- `OAuthClient` grows by ten fields. The struct is still small, but the in-memory and Postgres adapters both need an additive migration. The Postgres path requires a non-trivial migration with backfill defaults (`token_endpoint_auth_method` defaulting to `"client_secret_basic"` for existing clients to preserve current behaviour).
- Implementing RFC 7592 management endpoints adds a separate auth model (`registration_access_token`) alongside the existing `client_secret` auth. Two credentials per client (only one of which most callers ever see) is more surface than no registration support. The trade buys clients the ability to self-manage; the alternative — registration without management — is RFC 7591-only and produces orphaned configurations that only an operator can fix.
- Rejecting `software_statement` outright means the platform cannot participate in federations that use signed client metadata. Acceptable for the reference implementation; a future ADR can add it with a trust anchor list.

## Alternatives Considered

- **Replace `POST /clients` with `POST /register`.** Smaller surface. Rejected because the auth models differ (admin vs public) and the field sets differ (operator-friendly vs RFC 7591). Forcing them through one route would either weaken the admin model or break the RFC 7591 spec. The cost of two endpoints is low; the benefit is that each surface optimises for its caller.
- **Require an initial access token by default (gated registration).** Spam-resistant; matches Auth0's model. Rejected because the reference implementation's promise is "runnable with zero pre-config." A fresh `docker compose up` should let a developer register a client and test the flow. Operators in production are expected to set `CLIENT_REGISTRY_INITIAL_ACCESS_TOKEN` and document its distribution — that knob is one env var.
- **Default `token_endpoint_auth_method` to `client_secret_basic`** (RFC 7591 §2's spec default). Rejected because the dominant use case here is public clients (MCP, SPAs). Defaulting to confidential would force every connector to either provide `token_endpoint_auth_method: "none"` explicitly or carry a secret it cannot protect. Inverting the default trades one surprise (operators expecting RFC default) for hundreds of correctly-registered MCP clients.
- **Skip RFC 7592 (registration without management).** Simpler. Rejected because it strands every dynamically-registered client at its initial configuration — change a redirect URI and the client must be re-registered, breaking continuity. The management endpoints are roughly half the spec but add only marginal implementation cost on top of the registration handler.
- **Implement `software_statement` verification with a static trust anchor.** Brings the platform into federation scenarios. Rejected as scope-creep for this ADR — federations have their own design space (which anchors, key rotation, claim mapping) and deserve a dedicated ADR. Easier to add than to retrofit; deferring loses nothing.
- **Couple `DELETE /register/{client_id}` to token revocation.** Cleaner-feeling — deregistration also kills the client's outstanding access. Rejected because revocation cascades are a separate concern (every issued token, every issued refresh token, every issued authorization code) and conflating them with metadata deletion makes both harder to reason about. A future "revoke client" admin operation can do the cascade explicitly.
