# ADR-0012: Authorization Server Metadata (RFC 8414 + OIDC Discovery)

**Status**: Accepted
**Date**: 2026-06-23

## Context

ADRs 0008–0011 give the platform a fully working OAuth 2.1 + OIDC stack — RS256 + JWKS, authorization code + PKCE, ID tokens, and a unified login service. The next consumer to bring online is the **client library** on the other end: MCP connectors, OIDC client libraries (e.g. `oidc-client-ts`, `python-oauthlib`, Authlib, Auth0 SDKs, NextAuth), and any future federated relying party. Every one of those libraries expects to bootstrap itself from a single URL — the issuer — and discover every endpoint, key set, and capability from a JSON document at a well-known path.

Without that document, every integration costs a paragraph of bespoke configuration: "the token endpoint is at `/oauth/token`, the userinfo endpoint is at `/userinfo`, the JWKS is at `/.well-known/jwks.json`, the supported scopes are `openid email profile read write`, PKCE is required, only RS256 is supported, only the authorization code grant is allowed, …". Every one of those facts is already true; what is missing is the machine-readable surface that lets a client *learn* them in one HTTP GET.

Two specifications cover this:

- **RFC 8414** — OAuth 2.0 Authorization Server Metadata. Well-known path: `/.well-known/oauth-authorization-server`.
- **OpenID Connect Discovery 1.0** — Well-known path: `/.well-known/openid-configuration`.

The two documents have substantially overlapping fields (issuer, endpoints, supported algorithms, supported scopes). OIDC Discovery is a superset for the OIDC-specific fields (`userinfo_endpoint`, `id_token_signing_alg_values_supported`, etc.). RFC 8414 is the broader OAuth 2.0 spec. Modern client libraries query whichever URL their author wrote first. Serving **both** at distinct well-known paths is what every interoperable provider does.

## Decision

Expose two server-metadata endpoints on `auth-server`, both unauthenticated, both cacheable, both serving the same merged metadata document (specialised per spec where the field sets differ):

- `GET /.well-known/oauth-authorization-server` — RFC 8414
- `GET /.well-known/openid-configuration` — OIDC Discovery 1.0

The metadata is **derived from the running configuration at startup** (a single composition step in `container.go`), held in memory, and served from a single handler. Operators do not author a JSON file by hand — every value is sourced from the same config that drives the rest of the service, so the document cannot drift away from runtime behaviour.

### Issuer URL

The issuer is the single identifier every other field is anchored to. It MUST be:

- A URL using the `https` scheme (production) — `http` allowed in dev fallback.
- Identical to the `iss` claim on every access token and ID token (RFC 9068 §2.2, OIDC §2).
- Identical to the `iss` value in the metadata document itself.
- **No** query string, **no** fragment.
- Trailing slash is significant — RFC 8414 §3 is strict. The implementation normalises by stripping a trailing slash and emits the form without it.

Source: the `AUTH_OIDC_ISSUER` env var introduced in ADR-0010. Startup fails if it is unset or malformed.

### Endpoint URLs

Every endpoint URL in the metadata is built by joining the issuer with the path served by the corresponding handler. There is no second source of truth — the same constant that the router registers is the one the metadata advertises. A handler that goes away takes its metadata entry with it.

| Metadata field | Handler |
|---|---|
| `authorization_endpoint` | `auth-server` `GET /oauth/authorize` (the `login-ui` sign-in / consent surfaces from ADR-0011 are **implementation details** of this endpoint, not separately advertised — clients only know about `authorization_endpoint`) |
| `token_endpoint` | `auth-server` `POST /oauth/token` |
| `revocation_endpoint` | `auth-server` `POST /oauth/revoke` |
| `introspection_endpoint` | `auth-server` `POST /oauth/introspect` |
| `userinfo_endpoint` | `auth-server` `GET/POST /userinfo` (ADR-0010) |
| `jwks_uri` | `auth-server` `GET /.well-known/jwks.json` (ADR-0008) |
| `registration_endpoint` | `client-registry-service` `POST /clients` — **only emitted once ADR-0013 lands**; omitted until then |
| `end_session_endpoint` | `login-ui` `POST /sign-out` (ADR-0011) |

The `registration_endpoint` field is **conditional** — the metadata handler reads it from a config value (`AUTH_REGISTRATION_ENDPOINT`); when unset, the field is omitted entirely (not emitted as null or empty string). RFC 8414 §2 allows omission; emitting an empty value would mislead clients into POSTing to the issuer root.

### Capability fields

These advertise the platform's actual behaviour after ADRs 0008–0011. The values match what the code enforces; a mismatch is a release-blocking bug.

| Field | Value | Source |
|---|---|---|
| `response_types_supported` | `["code"]` | ADR-0009 — code flow only |
| `grant_types_supported` | `["authorization_code", "refresh_token", "client_credentials"]` | Registered strategies in `GrantStrategyRegistry` |
| `subject_types_supported` | `["public"]` | OIDC §8 — no pairwise subjects |
| `id_token_signing_alg_values_supported` | `["RS256"]` | ADR-0008 |
| `token_endpoint_auth_methods_supported` | `["client_secret_basic", "client_secret_post", "none"]` | Confidential clients use Basic or form-body; public clients (ADR-0009) use `none` + PKCE |
| `code_challenge_methods_supported` | `["S256"]` | ADR-0009 — PKCE mandatory, S256 only |
| `scopes_supported` | `["openid", "profile", "email", "read", "write"]` | OIDC scopes (ADR-0010) plus existing resource scopes |
| `claims_supported` | `["sub", "iss", "aud", "exp", "iat", "nonce", "at_hash", "auth_time", "amr", "email", "email_verified", "name", "updated_at"]` | ADR-0010 |
| `claim_types_supported` | `["normal"]` | OIDC §5.6 — no aggregated/distributed claims |
| `request_parameter_supported` | `false` | We do not implement `request=` JWT (OIDC §6.1) |
| `request_uri_parameter_supported` | `false` | We do not implement `request_uri=` (OIDC §6.2) |
| `require_request_uri_registration` | `false` | Moot when the above is false; emitted for spec strictness |
| `service_documentation` | `https://github.com/ocrosby/identity-platform-go/blob/main/README.md` | Static URL |
| `op_policy_uri` | `""` (omitted) | No platform-wide policy document |
| `op_tos_uri` | `""` (omitted) | No platform-wide terms-of-service document |
| `ui_locales_supported` | `["en"]` | login-ui currently English-only |

`revocation_endpoint_auth_methods_supported`, `introspection_endpoint_auth_methods_supported` echo the same set as `token_endpoint_auth_methods_supported`. RFC 7009 / RFC 7662 require these to be advertised when their respective endpoints exist.

### Response shape and caching

```http
GET /.well-known/oauth-authorization-server
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=3600
```

`Cache-Control: public, max-age=3600` matches the JWKS endpoint's caching (ADR-0008). Both are static for the lifetime of a deployment — a redeploy that changes a value is also a redeploy that invalidates the upstream cache.

The body is the same JSON object for both well-known paths, with three OIDC-only fields (`userinfo_endpoint`, `id_token_signing_alg_values_supported`, `claims_supported`, `subject_types_supported`) emitted regardless of which URL is queried. RFC 8414 does not forbid the extra fields; OIDC Discovery requires them. A single document for both URLs is operationally simpler than maintaining two.

### What is NOT advertised

These exist but are deliberately omitted:

- **`/internal/issue-code` on `auth-server`** (ADR-0011) — internal-only, bearer-authenticated with a service token, not part of any public protocol.
- **`/users/{id}/claims` on `identity-service`** (ADR-0010) — internal projection consumed by `/userinfo`, not callable by clients.
- **`/clients/{id}/display` on `client-registry-service`** (ADR-0011) — public-safe but not part of the OAuth/OIDC protocol surface; clients should not call it directly.
- **The fly-internal hostnames** (`*.internal`) used for inter-service traffic — every advertised URL uses the public issuer host.

Advertising a private endpoint in metadata would tell a curious client that it can be called; the principle is to leak no operational information the spec does not require.

### Validation at startup

`auth-server` validates the metadata document at startup before serving traffic. The check has three parts:

1. **Issuer URL well-formed** — `https://` (or `http://localhost…` in dev), no query, no fragment.
2. **Every advertised endpoint resolves to a registered route** — the handler that emits the metadata reads the same router that serves requests. A field whose backing handler is not registered is a startup error.
3. **Every advertised algorithm/method is implemented** — `RS256` must be the signing alg in the running token generator; `S256` must be the PKCE method the code flow enforces. A mismatch is a startup error.

These three checks catch the common drift scenarios — a route renamed without updating metadata, a config that says RS256 while the token generator is still configured for HS256, an issuer URL with a trailing slash. The cost is a few dozen lines of code at startup; the benefit is that "the metadata document was correct at deploy time" is a build-time guarantee, not a thing operators have to remember to test.

### Configuration surface

No new env vars beyond what ADRs 0008–0011 already added. `AUTH_OIDC_ISSUER` (ADR-0010) is the issuer; everything else is derived.

One conditional: `AUTH_REGISTRATION_ENDPOINT` is read by `auth-server` at startup and, when set, becomes the `registration_endpoint` value. The variable is **operator-set at deploy time** — it carries the public URL of `client-registry-service`'s RFC 7591 `/register` endpoint (ADR-0013). There is no runtime discovery; the value is part of the deployment configuration, the same way `AUTH_CLIENT_REGISTRY_URL` is today. When unset, the field is omitted entirely (RFC 8414 §2 allows omission).

### Compile-time interface check

```go
var _ ports.MetadataProvider = (*MetadataProvider)(nil)
```

## Consequences

**Positive**

- Every OIDC-compliant client library — Auth0 SDKs, NextAuth, `oidc-client-ts`, `Authlib`, `python-oauthlib`, the MCP OIDC connector — can configure itself from one URL. The integration story for any new RP collapses to "set the issuer to `https://identity.example.com`."
- The metadata is generated from the running configuration, so a drift between "what we say we do" and "what we actually do" is caught at startup, not in a 3 AM debugging session against a confused client.
- Both well-known paths are served from one handler; supporting RFC 8414 *and* OIDC Discovery costs no extra runtime code beyond the route registration.
- Conditional emission of `registration_endpoint` means ADR-0013 can be merged without any metadata change beyond flipping an env var — the document stays correct at every intermediate state.

**Negative / Trade-offs**

- The metadata document is a public statement of the platform's capabilities. Once published, removing a `grant_types_supported` entry or narrowing `scopes_supported` is a breaking change for every integrated client. Mitigation: that constraint is the *point* — having to think before removing a capability is the discipline metadata gives you for free.
- Caching for 1 hour means a deploy that changes a metadata field (e.g. adds a scope) takes up to an hour to be visible to a client that has it cached. For the field set we serve today (slow-changing platform capabilities), this is the right trade. If a field becomes high-churn — e.g. `scopes_supported` getting frequent additions — the TTL should be lowered, not extended.
- Validating "every advertised endpoint resolves to a registered route" at startup couples the metadata package to the router. Tolerable: this coupling is the load-bearing assertion. Decoupling it would require either dynamic discovery (slow) or two sources of truth (drifts).
- Some OIDC client libraries query OIDC Discovery only; some query RFC 8414 only; some try one and fall back to the other. Supporting both is the right answer but means two routes for one logical resource. The maintenance cost is low because they serve the same document.

## Alternatives Considered

- **Serve only OIDC Discovery (`/.well-known/openid-configuration`).** Covers most clients. Rejected because the OAuth-only `client_credentials` clients that don't use OIDC still benefit from RFC 8414 discovery, and serving both costs nothing once the handler exists.
- **Author the metadata as a static JSON file checked into the repo.** Simpler implementation. Rejected because every redeploy has to remember to update it, and the most common drift bug is exactly that "we changed the route but forgot to update the metadata." Generating it from runtime config makes drift impossible.
- **Locate the metadata endpoint on `jk-api-gateway` (the public ingress).** The gateway is the public surface; metadata is a public concern. Rejected because the metadata describes `auth-server`'s capabilities — the closer the source is to those capabilities, the harder it is for them to disagree. `auth-server` knows what it supports; the gateway only knows where to proxy.
- **Emit `id_token_encryption_alg_values_supported` etc. with empty arrays.** Some implementers do this. Rejected because RFC 8414 §2 says to omit fields whose value is empty, not to advertise empty support; explicit emptiness can mislead a client into trying to negotiate it.
- **Cache for 24 hours instead of 1 hour.** Standard pick for well-known documents that change infrequently. Rejected for the platform's current life stage: a 24-hour cache makes early debugging painful. We can extend the TTL once the metadata stabilises.
