# ADR-0024: Step-Up Authentication Challenge (RFC 9470)

**Status**: Accepted
**Date**: 2026-07-08

## Context

Today, once a client holds a valid access token, `example-resource-service` gates access purely on scope (`RequireScopeMiddleware`, `services/example-resource-service/internal/adapters/inbound/http/middleware.go`). There is no way for a resource server to say "this token is valid and has the right scope, but the user behind it needs to re-authenticate more strongly before I'll allow this specific action" — e.g., a funds-transfer endpoint that should require a *fresh* login even if the caller already holds a long-lived, scope-sufficient token. RFC 9470 defines exactly this signal: a `WWW-Authenticate: Bearer error="insufficient_user_authentication"` challenge naming the `acr_values`/`max_age` that would satisfy it, which the client resolves by re-initiating authorization at the AS with those values.

Two existing pieces of plumbing are directly relevant:

- **`domain.LoginChallenge`** (`services/auth-server/internal/domain/login_challenge.go`) already carries `Prompt []string` and `MaxAge int`, parsed end-to-end from `/oauth/authorize`'s `prompt`/`max_age` query parameters (`handler.go`'s `authorizeRequest` → `parseAuthorizeRequest` → `persistChallengeAndRedirect`). `acr_values` has no equivalent today — no parsing, no field, nowhere to land.
- **`go-platform/jwtutil`'s `Claims`/`IDClaims`** — the shared, externally-versioned structs this platform signs into every JWT — have no `acr` field, and adding one means publishing a new version of a module outside this repo. This is the same category of constraint that pushed RFC 7638 JWK thumbprinting to be implemented locally rather than upstreamed (see the DPoP roadmap entry in `CLAUDE.md`); here the constraint is sharper, because there is no local workaround for a field that must live *inside a signed JWT this platform doesn't own the struct for*.

## Decision

Implement RFC 9470's client-facing challenge and the AS/RS round trip entirely through repo-owned types — `domain.LoginChallenge`, `domain.Token`, `domain.IntrospectResponse`, and `example-resource-service`'s own `IntrospectionResult` — none of which require touching `go-platform`. The satisfied authentication-context value travels through **the introspection response**, not through a JWT claim.

### Why introspection, not a JWT claim

`domain.IntrospectResponse` (RFC 7662 response, `services/auth-server/internal/domain/token.go`) is a JSON DTO this repo defines and controls — RAR (ADR-0017) already extended it with `authorization_details` for exactly this reason. Adding `acr` here needs no external dependency. The tradeoff, stated explicitly: **`acr` is only visible to a caller of auth-server's own `/oauth/introspect`.**

This is a narrower statement than "anything with `RESOURCE_INTROSPECTION_URL` set," discovered while implementing: `example-resource-service`'s documented, default introspection path is `services/token-introspection-service` — a separate microservice that validates JWTs **entirely locally** (HMAC or RS256+JWKS, `internal/adapters/outbound/jwt/{validator,rs256_validator}.go`) and **never calls auth-server at all**. Its response is built from `jwtutil.Claims` fields, which — per the Context section above — has no `acr` field to source from. So `acr` cannot reach `example-resource-service` through the standard, documented `example-resource-service` → `token-introspection-service` topology, full stop; not "only when `RESOURCE_INTROSPECTION_URL` is unset" as an earlier draft of this ADR assumed, but "not through this path at all, regardless of configuration." Adding a permanently-empty `Acr` field to `token-introspection-service`'s own `domain.IntrospectionResult` for forward-compatibility was considered and rejected — see Alternatives.

Given that, this ADR's `example-resource-service` work (`RequireACRMiddleware`, `contextKeyAcr`) is delivered as a **generic, correctly-shaped mechanism** — real code, real unit tests, wired to read from whatever `ports.TokenIntrospector` happens to populate — rather than a claim this repo can currently demonstrate end-to-end through the real service topology. The part that *is* fully real and end-to-end testable is entirely on the AS side: `/oauth/authorize` accepting `acr_values`, the issued token's `Acr` field, and auth-server's own `/oauth/introspect` echoing it back. The acceptance test for this ADR exercises that AS-side round trip; `RequireACRMiddleware` is exercised at the unit level only, the same level `RequireScopeMiddleware` itself is tested at.

### This platform's one authentication method

`login-ui` has exactly one authentication method (email + password) and no persistent browser session — every `authorization_code` redemption re-authenticates the user from scratch. There is no session state for `acr_values`/`max_age` to *elevate*: any authorization_code flow already performs a fresh, interactive login. Consequently:

- The satisfied ACR value is a **platform-wide constant**, `"pwd"` (informally borrowed from RFC 8176's registered AMR value of the same name — OIDC does not mandate specific ACR value semantics; a deployment defines its own), stamped unconditionally onto every token an `authorization_code` redemption issues.
- `client_credentials`, `refresh_token`, and `token_exchange` tokens carry no `acr` at all (empty/omitted) — there is no user behind those grants for an authentication-context claim to describe.
- `acr_values` is parsed and stored on `LoginChallenge` for protocol completeness (and advertised via `acr_values_supported` in RFC 8414 metadata) but does not branch `login-ui`'s behavior — there is only one method to satisfy it with. A deployment with a second authentication method (e.g., WebAuthn as a step-up factor) would branch on this field; that is out of scope here.

### The round trip

**Fully real, end-to-end (auth-server only):**
1. A client calls `/oauth/authorize` with `&acr_values=pwd` (or any value — stored regardless, see above).
2. `login-ui` runs its one real authentication method.
3. The issued access token's `domain.Token.Acr` is `AcrValuePassword`.
4. `POST /oauth/introspect` on that token returns `"acr": "pwd"`.

**Mechanism only, not wired to a real data source yet (`example-resource-service`):**
5. A route gated with `RequireACRMiddleware("pwd")`, layered under the existing `RequireScopeMiddleware` (mirrors that middleware's shape: panics on empty config, reads a new `contextKeyAcr`), returns:
   ```
   HTTP/1.1 401 Unauthorized
   WWW-Authenticate: Bearer realm="example-resource-service", error="insufficient_user_authentication", error_description="...", acr_values="pwd"
   ```
   for any request whose `contextKeyAcr` is empty or mismatched — which, given the topology limitation above, is every request through the real `token-introspection-service` path today. A future `ports.TokenIntrospector` implementation that does source `Acr` (e.g., one that calls auth-server's own `/oauth/introspect` instead of `token-introspection-service`) would light this up with no further code change — `IntrospectionAuthMiddleware` already copies `result.Acr` into context unconditionally.

## Consequences

### Positive

- Fully real, fully testable end-to-end (challenge → re-authorize → retry → success) without touching any dependency this repo doesn't own.
- Reuses every established pattern: `LoginChallenge`'s existing `Prompt`/`MaxAge` parse-and-store shape, RAR's precedent for extending `IntrospectResponse`, `RequireScopeMiddleware`'s panic-on-misconfiguration + context-lookup shape.

### Negative

- **`acr` does not reach `example-resource-service` through its documented, default topology** (`token-introspection-service`, local JWT validation) at all — a bigger gap than "requires `RESOURCE_INTROSPECTION_URL`, same as revocation." `RequireACRMiddleware` is real, tested code with nothing real to read from in the standard deployment today. Closing this fully would mean either publishing `acr` support in `go-platform/jwtutil` (out of reach) or teaching `token-introspection-service` to call auth-server's `/oauth/introspect` for this one field (a design change to a service this ADR did not set out to modify) — both deferred to a future ADR if step-up enforcement at the resource-server layer becomes a real requirement.
- Only one ACR value exists platform-wide (`"pwd"`) — a `RequireACRMiddleware` configured with any other value can never be satisfied by this reference implementation. This is intentional and stated, not a bug: a second authentication method is a separate, larger feature (a real step-up UI in `login-ui`) this ADR does not build.
- `acr_values` on `/oauth/authorize` is accepted and stored but does not alter `login-ui`'s behavior — see above.

## Alternatives Considered

- **Add `acr`/`auth_time` to `go-platform/jwtutil`'s `Claims`/`IDClaims`.** Rejected — out of reach from this repo (separate module, separate release cycle); would also make the claim visible on the raw JWT to parties who never call introspection, which is a bigger exposure surface change than this ADR intends to make.
- **Add a permanently-empty `Acr` field to `token-introspection-service`'s `domain.IntrospectionResult` for forward-compatibility.** Rejected — with no `jwtutil.Claims.Acr` to source it from, the field would always be empty/omitted; a speculative field with no current data source is exactly the kind of dead-weight addition this codebase's own complexity/pragmatism conventions warn against.
- **Teach `token-introspection-service` to call auth-server's `/oauth/introspect` for `acr` specifically.** Rejected for this ADR — it would compromise that service's whole reason for existing (local, no-network-round-trip validation) for the sake of one field; a future ADR can revisit if resource-server-side step-up enforcement becomes a real requirement, and could special-case just the `acr` lookup rather than replacing local validation wholesale.
- **Fake a per-request "step-up" by re-checking scope more strictly.** Rejected — conflates authorization (scope) with authentication strength (RFC 9470's actual subject); the whole point of RFC 9470 is that these are orthogonal.
- **Model multiple ACR values / a real step-up UI in `login-ui` now.** Rejected — `login-ui` has one authentication method; building a second one (e.g., a TOTP/WebAuthn step-up form) to make ACR selection meaningful is a substantially larger feature than this ADR's scope and can follow once there is a second method to select between.

## References

- [RFC 9470 — OAuth 2.0 Step Up Authentication Challenge Protocol](https://datatracker.ietf.org/doc/html/rfc9470)
- [RFC 8176 — Authentication Method Reference Values](https://datatracker.ietf.org/doc/html/rfc8176)
- [RFC 6750 §3 — Bearer Token Usage, WWW-Authenticate Response Header Field](https://datatracker.ietf.org/doc/html/rfc6750#section-3)
- [ADR-0010 — OIDC Core](0010-oidc-core.md)
- [ADR-0011 — Login-UI Service and the Login-Challenge Handoff](0011-login-ui-service.md)
- [ADR-0017 — Rich Authorization Requests (RFC 9396)](0017-rich-authorization-requests-rfc-9396.md)
