# ADR-0011: Unified Login & Registration Service (`login-ui`)

**Status**: Accepted
**Date**: 2026-06-23

## Context

ADR-0009 (authorization code + PKCE) and ADR-0010 (OIDC Core) leave one gap before any human can sign in: there is no user-agent surface that authenticates the user, captures consent, and feeds the result back into the `/oauth/authorize` flow. `auth-server` is the OAuth/OIDC protocol surface — it must remain framework- and UI-agnostic — and `identity-service` owns the user data but has no rendering layer. The design call left open in earlier conversation has now been made: this functionality lives in a **separate, multi-tenant login service** that hosts login *and* registration for every relying party (RP) that integrates with the platform.

Two consequences follow from "multi-tenant":

1. **Shared session.** A user who signs in to RP-A should not have to sign in again immediately to RP-B during the same SSO session window. The login service is the OP's single sign-on surface, not RP-A's login screen.
2. **Per-RP branding.** The same user-facing pages must adapt to the requesting client — name, logo, requested scopes, link to the RP's terms — without leaking branding from one RP into another's flow.

`identity-service` already exposes the JSON endpoints the login service needs (`POST /auth/login`, `POST /auth/register`, `POST /auth/request-verification`, `POST /auth/verify-email`) and ADR-0009 already defined the `AuthorizationCodeIssuer` port that the login service will call once the user is authenticated and has consented. So the work is to introduce a new HTTP service, define the protocol between it and `auth-server`, and pin down the session and CSRF mechanics.

## Decision

Introduce a new service, **`login-ui`** (port `8087`), that owns every user-facing screen in the identity platform: sign-in, sign-up, email verification redemption, consent, and (later) password reset. `auth-server` remains the OAuth/OIDC protocol surface and stays UI-free; `identity-service` continues to be the user record store and stays OAuth-unaware. The two existing services gain no new responsibilities — `login-ui` is the integration point.

```
   RP (browser)                                    auth-server                      login-ui                       identity-service
   ─────────────                                   ───────────                      ────────                       ────────────────
    GET /oauth/authorize?response_type=code… ────►
                                                  has SSO cookie? no
                                                  ◄──── 302 /sign-in?login_challenge=<id>
    GET /sign-in?login_challenge=<id> ─────────────────────────────────────────────►
                                                                                    POST /auth/login ────────────► verify creds
                                                                                    ◄──────────────────────────── user_id
                                                                                    set SSO cookie, store session in Redis
                                                                                    consent needed? yes
                                                                                    render consent screen
    POST /consent?login_challenge=<id> approve ───────────────────────────────────►
                                                                                    POST /internal/issue-code on auth-server ►
                                                  validate login session, issue code
                                                  ◄──────────────────────────────── code
                                                                                    ◄── code
                                                  ◄──── 302 RP_redirect_uri?code=…
    GET RP_redirect_uri?code=… ◄─────────────────
    (RP exchanges code at /oauth/token)
```

### Service boundaries — what each service owns

| Service | New / changed responsibilities |
|---|---|
| `login-ui` (new) | All HTML rendering; CSRF defence; per-RP branding lookup; sign-in / sign-up form POST handling; reads & writes SSO session in Redis; calls `identity-service` for credentials and registration; calls `auth-server` to redeem login + consent into an authorization code |
| `auth-server` | Adds `/oauth/authorize` proper implementation; introduces a short-lived **login challenge** that hands the original authorize request to `login-ui` opaquely; gains a new internal-only `POST /internal/issue-code` endpoint that `login-ui` calls to redeem an authenticated, consented login challenge into an authorization code |
| `identity-service` | No new endpoints from this ADR — existing `/auth/login`, `/auth/register`, `/auth/request-verification`, `/auth/verify-email` are reused. (ADR-0010 adds one internal endpoint, `GET /users/{id}/claims`, consumed by `auth-server`'s `/userinfo` — not by `login-ui`.) |
| `client-registry-service` | Exposes a new public-safe projection at `GET /clients/{id}/display` returning `display_name`, `logo_uri`, `tos_uri`, `policy_uri` — used by `login-ui` for branding without leaking secrets |

### The login challenge

The `/oauth/authorize` request carries 8–10 parameters (`response_type`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method`, `nonce`, `prompt`, `max_age`). Putting them all in the query string when redirecting to `login-ui` is fragile (URL-length limits, log leakage, easy to lose `state` integrity). Instead, `auth-server` stores the validated authorize request server-side and hands `login-ui` a short opaque identifier — the **login challenge**.

```go
type LoginChallenge struct {
    ID                  string    // opaque, 32 bytes hex
    ClientID            string
    RedirectURI         string    // already validated against client.RedirectURIs
    Scopes              []string  // already intersected with client.Scopes
    State               string    // RP-supplied; round-tripped, not interpreted
    Nonce               string    // OIDC §3.1.2.5
    CodeChallenge       string    // PKCE
    CodeChallengeMethod string    // "S256"
    Prompt              []string  // "none" | "login" | "consent" | "create" parsed values
    MaxAge              int       // OIDC §3.1.2.1 — re-auth required if older than this
    SessionID           string    // populated by login-ui once the user authenticates
    ConsentGranted      []string  // populated by login-ui once consent is granted
    CreatedAt           time.Time
    ExpiresAt           time.Time // CreatedAt + 5 min
}
```

A `LoginChallengeRepository` (memory + Redis adapters per ADR-0006) stores these. TTL is 5 minutes — enough for a careful user to read a consent screen, short enough that abandoned challenges expire quickly. `login-ui` mutates the challenge during the flow (sets `SessionID` after login, sets `ConsentGranted` after consent) by calling `auth-server`; `login-ui` never reaches into the store directly.

### Shared SSO session

The platform issues a single SSO session cookie per browser, scoped to the parent domain shared by `auth-server` and `login-ui`. The session is server-side state in Redis; the cookie carries only an opaque identifier.

| Property | Value |
|---|---|
| Cookie name | `__Host-sso_session` |
| `Path` | `/` |
| `Secure` | `true` |
| `HttpOnly` | `true` |
| `SameSite` | `Lax` — required so the cookie is sent on the RP-initiated cross-site GET to `/oauth/authorize`; `Strict` would block that |
| Domain | (omitted — `__Host-` prefix forbids `Domain` attribute; the cookie is host-locked to the issuing host) |
| TTL | Idle: 30 min (default); absolute: 12 h (configurable) |

Because `__Host-` requires no `Domain` attribute, `auth-server` and `login-ui` must be reachable on the **same host** (e.g. both behind `https://identity.example.com`) in production. In docker-compose dev, both run under `localhost` with different ports, which works because cookies ignore port in the same-origin check for cookies (browsers treat `localhost:8080` and `localhost:8087` as the same host for cookies).

> **Deployment constraint behind `jk-api-gateway`:** the gateway must front both services on the same public hostname (path-prefix routing — `/oauth/*` → auth-server, `/sign-in`, `/sign-up`, `/consent`, `/sign-out` → login-ui — under one origin). If the gateway terminates TLS and forwards to disjoint internal hostnames, that is fine; what matters is that the browser sees one origin. Splitting auth-server and login-ui onto separate public hostnames silently breaks SSO — the `__Host-` cookie is host-locked. ADR-0012 (server metadata) pins this single origin as the issuer URL.

Session value in Redis:

```
sso_session:<id>  →  { user_id, authenticated_at, last_seen, amr: ["pwd"] }
```

`auth-server`'s `/oauth/authorize` looks up the cookie's session ID via a new `SessionStore` port and skips the redirect to `login-ui` when:

- A valid session exists, **and**
- `authenticated_at` is recent enough to satisfy any `max_age` parameter, **and**
- `prompt` does not contain `login`.

### Consent

Consent is stored per `(subject, client_id)`. Once a user has granted a set of scopes to a client, future authorize requests for the **same or a subset of** those scopes skip the consent screen; a request for a scope not previously granted re-prompts.

```go
type Consent struct {
    Subject     string
    ClientID    string
    Scopes      []string // sorted, unique
    GrantedAt   time.Time
}

type ConsentRepository interface {
    Get(ctx context.Context, subject, clientID string) (*Consent, error)
    Save(ctx context.Context, c *Consent) error
    Revoke(ctx context.Context, subject, clientID string) error
}
```

Stored on `auth-server` because it is bound to the OAuth identity model (subject + client). Memory + Postgres adapters following ADR-0007. A future ADR can add a user-facing "applications you've granted access to" page on `login-ui` that calls `Revoke`.

### `auth-server` internal endpoint — `/internal/issue-code`

`login-ui` redeems a completed login challenge by calling:

```
POST /internal/issue-code
Authorization: Bearer <LOGIN_UI_SERVICE_TOKEN>
Content-Type: application/json

{ "login_challenge": "<id>", "session_id": "<sso_session_id>", "consent_granted": ["openid", "email", "profile"] }
```

`auth-server` validates the challenge exists and is unexpired, validates the session exists and belongs to the same user the challenge was started for (or is being newly bound — first-time login), confirms the requested scopes match the granted scopes, then calls `ports.AuthorizationCodeIssuer.Issue` (ADR-0009) with an `IssueCodeRequest` built from the stored `LoginChallenge` (including its `Nonce`). The port returns the raw code only; the `/internal/issue-code` HTTP handler wraps the result by reading `RedirectURI` and `State` directly from the same `LoginChallenge` record and returning them in the response shape below:

```
200 OK
{ "code": "abc123…", "redirect_uri": "https://rp.example.com/callback", "state": "xyz" }
```

`login-ui` then 302s the user-agent to `<redirect_uri>?code=<code>&state=<state>`.

The endpoint is bearer-authenticated with a service token (`LOGIN_UI_SERVICE_TOKEN`) shared between `auth-server` and `login-ui`. This is **not** a user-facing endpoint and not advertised in RFC 8414 metadata.

### `login-ui` HTTP surface

| Route | Method | Purpose |
|---|---|---|
| `/sign-in` | GET | Render login form; reads `?login_challenge=<id>` query |
| `/sign-in` | POST | Submit credentials → calls `identity-service POST /auth/login` |
| `/sign-up` | GET | Render registration form |
| `/sign-up` | POST | Submit registration → calls `identity-service POST /auth/register` |
| `/verify-email` | GET | Renders "check your email" page |
| `/verify-email/{token}` | GET | Redeems verification token via `identity-service` |
| `/consent` | GET | Renders consent screen; reads `?login_challenge=<id>` |
| `/consent` | POST | Approve / deny → calls `auth-server POST /internal/issue-code` |
| `/sign-out` | GET/POST | OIDC RP-Initiated Logout 1.0 endpoint. Revokes SSO session; validates optional `post_logout_redirect_uri` against the client's registered `post_logout_redirect_uris` (a new field on `domain.Client`); on success returns `302` to the validated target, or `200` if no target was given. Both GET and POST are accepted per OIDC RP-Initiated Logout §3. |
| `/health` | GET | Health check |

### Open-redirect defence

Every redirect-to-RP path validates the destination against the stored `LoginChallenge.RedirectURI` (which was itself validated against the client's registered list in `auth-server`). `login-ui` never accepts a redirect target from the form body — it always reads it from the server-side challenge. Logout's `post_logout_redirect_uri` (an OIDC RP-Initiated Logout 1.0 parameter) must be on the client's registered `post_logout_redirect_uris` list — a new field on `domain.Client` to be added.

### CSRF defence

Every POST endpoint requires a double-submit CSRF token:

1. On `GET /sign-in` (and every other GET that produces a form), `login-ui` sets a `__Host-csrf` cookie carrying a random 32-byte token.
2. The rendered form includes a hidden `csrf_token` field with the same value.
3. On POST, the handler compares the cookie value to the form value with `subtle.ConstantTimeCompare`. Mismatch → `403 Forbidden`.

`Origin` and `Referer` headers are *additionally* validated against the configured public origin. Missing both → `403`.

### Rate limiting

`login-ui` applies fixed-window rate limits identical in shape to the existing `auth-server` limiter:

| Endpoint | Limit | Key |
|---|---|---|
| `/sign-in` POST | 10 per 60s | `(ip, email)` |
| `/sign-up` POST | 3 per 60s | `ip` |
| `/verify-email/{token}` | 20 per 60s | `ip` |

A bot-defence hook (CAPTCHA) is **not** in this ADR but the registration handler is structured to allow inserting one (a `BotDefender` port returning `Pass / Challenge / Block`).

### Account enumeration defence

`/sign-up` returns the same response shape whether the email is new or already registered. `identity-service POST /auth/register` already returns a generic 4xx for the "email exists" case; `login-ui` does not echo that detail to the page — the user sees "If this email isn't already registered, you'll receive a verification message shortly."

### Per-RP branding

The consent and sign-in screens display the requesting client's `display_name` and (when present) `logo_uri`. `login-ui` calls `client-registry-service GET /clients/{id}/display` once per challenge and caches the result in-process for the challenge's TTL (5 min). When `client_id` is unknown or the call fails, `login-ui` falls back to the platform-wide branding ("Identity Platform").

`logo_uri` is rendered with a strict CSP that restricts `img-src` to a configured allowlist of trusted hosts. A malicious client cannot inject script via the logo because it is rendered as an `<img>` only, but it could still pixel-track; the allowlist prevents that for the reference implementation. Production deployments will likely want a proxy that re-hosts logos.

### Project layout

`services/login-ui/` follows the standard ports & adapters layout (see top-level CLAUDE.md):

```
services/login-ui/
├── cmd/main.go
├── internal/
│   ├── config/
│   ├── domain/             # Session, ChallengeView, BrandingInfo
│   ├── application/        # SignInFlow, SignUpFlow, ConsentFlow
│   ├── ports/              # Inbound (HTTP) + Outbound (identity, authserver, registry, sessions)
│   └── adapters/
│       ├── inbound/http/   # Handlers, templates, middleware (CSRF, rate limit)
│       │   └── templates/  # Go html/template files — server-rendered, no JS framework
│       └── outbound/
│           ├── identity/   # POST /auth/login, etc.
│           ├── authserver/ # POST /internal/issue-code
│           ├── clientreg/  # GET /clients/{id}/display
│           ├── redis/      # SSO session + CSRF token store
│           └── memory/     # Local dev fallback for the above
```

HTML rendering uses Go's `html/template` (autoescape on by default — XSS-safe). No client-side framework. Server-rendered HTML keeps the trust boundary tight: every value the browser sees has been escaped on its way out.

### Configuration surface

| Variable | Default | Purpose |
|---|---|---|
| `LOGIN_UI_SERVER_HOST` | `0.0.0.0` | Bind host |
| `LOGIN_UI_SERVER_PORT` | `8087` | Bind port |
| `LOGIN_UI_PUBLIC_ORIGIN` | (required) | e.g. `https://identity.example.com` — used for `Origin` validation and absolute URL building |
| `LOGIN_UI_AUTH_SERVER_URL` | (required) | e.g. `http://auth-server:8080` — internal URL to call `/internal/issue-code` |
| `LOGIN_UI_IDENTITY_SERVICE_URL` | (required) | e.g. `http://identity-service:8081` |
| `LOGIN_UI_CLIENT_REGISTRY_URL` | (required) | e.g. `http://client-registry-service:8082` |
| `LOGIN_UI_REDIS_URL` | unset → memory fallback | SSO session + CSRF token store |
| `LOGIN_UI_SERVICE_TOKEN` | (required) | Bearer token for `/internal/issue-code` |
| `LOGIN_UI_SESSION_IDLE_TTL` | `30m` | Idle SSO session TTL |
| `LOGIN_UI_SESSION_ABSOLUTE_TTL` | `12h` | Absolute SSO session TTL |
| `LOGIN_UI_LOGO_ALLOWLIST` | `""` | Comma-separated allowlist of hosts for client `logo_uri` (empty → no logos rendered) |
| `AUTH_LOGIN_UI_URL` | (on `auth-server`) | e.g. `https://identity.example.com` — used to build the redirect to `/sign-in` |
| `AUTH_LOGIN_UI_SERVICE_TOKEN` | (on `auth-server`) | Must match `LOGIN_UI_SERVICE_TOKEN` |

### Compile-time interface checks

```go
var _ domain.LoginChallengeRepository = (*LoginChallengeRepository)(nil)
var _ domain.ConsentRepository = (*ConsentRepository)(nil)
var _ ports.SessionStore = (*SessionStore)(nil)
```

### What this ADR does NOT define

- **Password reset.** `identity-service` does not yet expose forgot/reset endpoints. Adding them is a separate, small ADR that mirrors the existing email-verification machinery — out of scope here.
- **Federated login** (Sign in with Google, GitHub, etc.). Separate ADR — would add an `IdentityProvider` strategy slot on `login-ui` and a corresponding linking flow on `identity-service`.
- **MFA.** Touches `identity-service` (factor storage), `auth-server` (`amr` claim widening), and `login-ui` (second-factor step). Large enough to deserve its own ADR.
- **Account linking.** Same as federated login — separate ADR.
- **User profile editing.** Could live on `login-ui` later; not required for the OIDC-bringup work that motivated this ADR.

These are not punted because they are uninteresting — they are punted because each is large enough to deserve scrutiny on its own terms, and bringing OIDC + MCP to "works end-to-end" does not require them.

## Consequences

**Positive**

- The platform now has a single, brandable sign-in surface that every RP — web app, MCP connector, future native app — redirects to. Users get SSO across RPs in the same browser session.
- `auth-server` stays a pure OAuth/OIDC protocol surface — no HTML templates, no CSRF tokens, no branding logic creeping in. The boundary in CLAUDE.md ("OAuth 2.0 authorization server") holds.
- `identity-service` stays out of the OAuth protocol — same JSON endpoints it already has, called by a different consumer (`login-ui` instead of the old direct `UserAuthenticator` path).
- The login-challenge indirection makes the authorize → login round trip URL-length-bounded and tamper-evident: the user cannot edit any of the protocol parameters by hand, because they live in a server-side record keyed by the opaque challenge ID.
- Consent storage means returning users do not re-consent on every authorize. Scope expansion still re-prompts, which is the right default.

**Negative / Trade-offs**

- One more deployable service. More YAML, another Fly app, another health check, another set of runbook entries.
- The shared SSO session requires `auth-server` and `login-ui` to share a host (or be behind a gateway that presents a unified origin). Deploying them on disjoint domains breaks the `__Host-` cookie. The constraint is documented but is a new operational requirement.
- The `LOGIN_UI_SERVICE_TOKEN` is a long-lived shared secret between two services. Rotation needs the same coordination as `JWT_SIGNING_KEY` did before ADR-0008 — both services restart with the new value. Tolerable; a future ADR can swap this for a mutual-TLS or signed-JWT scheme if it becomes painful.
- Server-rendered HTML with no client-side framework is a deliberate choice that bounds the user-facing JS attack surface — but it also means future interactive features (e.g. password-strength meter, real-time email validation) will be plain progressive enhancement, not React. That is a feature, not a bug, for a login screen.
- `login-ui`'s logo allowlist starts empty in the reference implementation. Production deployments must configure it explicitly, or no client logos render. Conservative default; surfaces the privacy / tracking concern explicitly.
- The consent table is yet another piece of persistent state. `auth-server`'s data ownership is growing: tokens (Redis, ADR-0006), authorization codes (Redis, ADR-0009), login challenges (Redis, this ADR), consents (Postgres, this ADR). The store mix is becoming non-trivial; a future audit may consolidate.

## Alternatives Considered

- **Render login inside `auth-server`.** Smallest possible change. Rejected because the prompt was explicit: the login surface is *multi-tenant across web apps*, and embedding it in `auth-server` re-couples UI to protocol. The boundary cost of a separate service is paid once; the cost of un-mixing them later is much higher.
- **Pass the authorize parameters in the URL when redirecting to `login-ui`.** Avoids the `LoginChallenge` indirection. Rejected because (a) URL lengths get fragile fast with 10 params and a long `state`, (b) `code_challenge` and `nonce` end up in browser history and proxy logs, (c) the user can tamper with parameters between the two services unless we sign the bundle, which is just an opaque-challenge token with a worse interface.
- **Use the `auth-server` JWT as the SSO session.** Tempting — same token, same signing key. Rejected because SSO sessions are coarse-grained (browser-level) and access tokens are fine-grained (per request, per resource server). Coupling them ties session lifetime to access-token lifetime and forces users to re-authenticate every hour. Standard OPs separate the two.
- **`SameSite=Strict` on the SSO cookie.** Stronger CSRF defence on the cookie itself. Rejected because the cookie must be sent on the RP-initiated cross-site GET to `/oauth/authorize`. `SameSite=Lax` allows that for top-level navigations and still blocks the dangerous cross-site POST cases.
- **Single Page App for `login-ui` (React/Vue).** Faster perceived performance, richer interactivity. Rejected for the reference implementation because the trust model of a server-rendered HTML form is dramatically simpler — every value the user sees has been escaped on its way out; there is no XSS surface beyond the templating layer. A production deployment that wants an SPA can replace the HTTP surface without touching the application layer.
- **Embed `login-ui` as a static-asset bundle served by `auth-server`.** Compromises: shares the deployable but keeps the rendering co-located with protocol code. Rejected for the same reason as the "render login inside `auth-server`" alternative — UI churn would land in the OAuth server.
