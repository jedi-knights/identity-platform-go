# Handoff — identity-platform-go

Snapshot of where the platform is and what's left to finish the original brief: **end-user signup + OAuth 2.1 + PKCE + JWKS for MCP connectors and a web app**.

Last session ended at commit `b3bdd77` on `main`.

## What's shipped

All four currently-implemented ADRs are merged to `main` and tagged:

| ADR | Title | Key endpoints / outcomes |
|---|---|---|
| 0008 | RS256 + JWKS | `/.well-known/jwks.json`; verifiers no longer need a shared HMAC secret |
| 0009 | Authorization code + PKCE-S256 | Full 12-step token-endpoint pipeline; public + confidential clients; atomic Consume on the code repo |
| 0010 | OIDC Core 1.0 | `id_token` issuance with `nonce` + `at_hash`; `/userinfo`; `openid`/`profile`/`email` scopes |
| 0011 | login-ui sign-in surface | `/oauth/authorize` persists a LoginChallenge and 302s to `login-ui/sign-in`; bearer-authed `/internal/issue-code` redeems it into an authorization code |

The current state lets a **single user sign in to one relying party** through a real OAuth 2.1 + OIDC flow.

## What's left — explicit roadmap

### Drafted ADRs, not implemented

| ADR | Title | Why it matters | Approx. effort |
|---|---|---|---|
| 0012 | Authorization Server Metadata (RFC 8414) | `/.well-known/oauth-authorization-server`. Without it every OAuth/OIDC client has to be hand-wired with each endpoint URL. | Small — 1 endpoint + tests |
| 0013 | Dynamic Client Registration (RFC 7591) | `POST /register`. This is the **MCP connector unblock** — without DCR every MCP client must be manually registered via client-registry-service. | Medium — builds on 0012 |
| 0014 | Refresh token rotation + replay detection | When a stolen refresh token is replayed, invalidate the entire token family. Security hardening. | Medium |

ADRs live under `docs/adr/0012-*.md` … `0014-*.md`.

### ADR-0011 follow-ups the ADR itself called out

These are non-blocking for the basic sign-in flow but are needed for a real product:

- [ ] **Sign-up screen on login-ui** — `identity-service POST /auth/register` exists; no UI calls it. Without this, "end-user signup" from the original brief is uncovered.
- [ ] **Consent screen** — `login-ui` currently sends `ConsentGranted: nil` so auth-server treats it as "grant all recorded scopes." A real consent UI + `GET/POST /consent` route is in the ADR.
- [ ] **SSO session cookie** — `login-ui` currently treats `session_id` as the subject ID directly. ADR-0011 spec defines a `__Host-`-prefixed `SameSite=Lax` cookie and a `SessionStore` port on `auth-server` so a returning user skips the form.
- [ ] **OIDC RP-Initiated Logout** — `GET/POST /sign-out` on login-ui; validates `post_logout_redirect_uri` against the client's registered list (new `post_logout_redirect_uris` field on `domain.Client`).
- [ ] **Email verification flow** — `/verify-email` on login-ui; identity-service likely needs an endpoint to redeem the verification token.

### Other open items

- **Task #19 — `TokenRepository.DeleteByCodeJTI` + replay cascade** (under ADR-0009). When an authorization code is replayed, invalidate all access/refresh tokens minted from it. Requires `jwtutil` upstream support for a `CodeJTI` field that ties tokens back to the code that birthed them.
- **End-to-end smoke test never run.** The ADR-0011 stack compiles, lints, and all unit tests pass, but no one has driven a full `authorize → sign-in → code → token` flow through `docker compose up` yet. Cheapest pre-flight check before stacking more layers.
- **login-ui Fly.io deploy config.** `.github/workflows/deploy.yml` matrix doesn't include `login-ui` — there's no `fly.login-ui.toml` yet. Decide whether login-ui ships to Fly.io or stays compose-only.

## How to verify the current `main` works

```bash
cp .env.example .env
# Edit .env: set LOGIN_UI_SERVICE_TOKEN to a fresh openssl rand -hex 32
# and the other passwords to non-default values.

docker compose up -d
docker compose ps   # all services healthy?
```

Then drive a flow (PKCE values are sample; generate fresh ones from `code_verifier` for any real check):

```bash
# 1. Hit /oauth/authorize — expect 302 to http://localhost:9087/sign-in?login_challenge=…
curl -i "http://localhost:9080/oauth/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:8080/cb&scope=openid&state=xyz&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&nonce=n-0S6_WzA2Mj"

# 2. Open the redirect Location in a browser, submit a test user from identity-service.
# 3. The browser should land at http://localhost:8080/cb?code=…&state=xyz.
```

If step 1 returns `501 not yet implemented`, then `AUTH_LOGIN_UI_URL` wasn't set on auth-server. If it 200s with a form rendered at login-ui but `POST` fails, check that `LOGIN_UI_SERVICE_TOKEN` matches on both sides (compose interpolates it from the same env var).

## Pending PRs / branches

- `origin/feat/password-reset` — 2 commits ahead of main: **substantive unmerged work** (identity-service password reset flow with `/auth/request-password-reset` and `/auth/reset-password`, separate token table, email sender extension, migrations). Decide whether to merge, rebase, or close. Tip: `gh pr list --state all --head feat/password-reset` to see PR history.

Local has been cleaned: only `main` remains; all other local branches were merged-and-deleted upstreams.

## Recommended next session

1. **Smoke-test the current `main`** with the steps above. Catches any compose / wiring bugs cheaply.
2. **Decide ADR-0012 vs sign-up screen vs password-reset merge** as the next focused chunk. The MCP-unblocking critical path is ADR-0012 → ADR-0013 (DCR). The end-user-signup brief item is the login-ui sign-up screen.
3. **Task #19** is small once `jwtutil` exposes `CodeJTI` upstream — bundle it into whichever security PR comes next.
