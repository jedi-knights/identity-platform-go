# Lago on Fly.io — Deployment & Rebuild Runbook

Self-hosted Lago (API + front + worker) with Managed Postgres and Upstash Redis.
Covers first-time deploy, rebuild-from-scratch, and common operational tasks.

**Related issues:** [#138 Epic 1](https://github.com/jedi-knights/identity-platform-go/issues/138), [#149 E1-S1](https://github.com/jedi-knights/identity-platform-go/issues/149), [#150 E1-S2](https://github.com/jedi-knights/identity-platform-go/issues/150)

## Prerequisites

- `flyctl` >= 0.3, authenticated as a member of the `jedi-knights` Fly org
- `openssl`, `jq`
- `FLY_ORG=jedi-knights` in the shell environment
- Read access to this repo

## Topology

| App             | Image                | Ports  | Purpose                              |
|-----------------|----------------------|--------|--------------------------------------|
| `jk-lago-api`   | `getlago/api:v1`     | 3000   | Lago REST API (Rails + Puma)         |
| `jk-lago-front` | `getlago/front:v1`   | 80     | Admin UI (React SPA, nginx-served)   |
| `jk-lago-worker`| `getlago/api:v1`     | —      | Sidekiq worker for background jobs   |
| `jk-lago-pg`    | Managed Postgres     | —      | Shared DB for api + worker           |
| `jk-lago-redis` | Upstash Redis        | —      | Sidekiq queue + Lago cache           |

All apps are **private** (no public IPv4). Reachable via Fly's `.internal`
6PN network. Public access to the admin UI is via the `api-gateway`
(separate repo) or `fly proxy` for admins.

## First-time deploy

```bash
export FLY_ORG=jedi-knights
./scripts/lago-bootstrap.sh --region iad
```

That script is idempotent: creates apps, provisions Postgres + Redis, attaches
them (`DATABASE_URL`, `REDIS_URL`), and sets the five shared secrets on both
`jk-lago-api` and `jk-lago-worker`. Then deploy:

```bash
fly deploy -c fly.lago-api.toml
fly deploy -c fly.lago-worker.toml
fly deploy -c fly.lago-front.toml
```

Run the initial DB migration (once, after the first API deploy):

```bash
fly ssh console -a jk-lago-api -C 'bundle exec rails db:migrate'
fly ssh console -a jk-lago-api -C 'bundle exec rails db:seed'
```

## Initial admin

Lago does not ship a default admin. Signup is disabled in production
(`LAGO_DISABLE_SIGNUP=true`), so the first admin is created via a one-shot
Rails runner inside the API container:

```bash
fly ssh console -a jk-lago-api
# inside the container:
bundle exec rails runner "
  org = Organization.create!(name: 'Jedi Knights')
  User.create!(
    email: ENV.fetch('BOOTSTRAP_ADMIN_EMAIL'),
    password: ENV.fetch('BOOTSTRAP_ADMIN_PASSWORD'),
    organizations: [org]
  )
"
```

Set `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` as *staged* Fly
secrets before running (`fly secrets set --stage -a jk-lago-api ...`), then
unset them after (`fly secrets unset -a jk-lago-api BOOTSTRAP_ADMIN_PASSWORD`).
The password never appears in this repo.

## Reaching the admin UI

Because the front app is private, reach it via `fly proxy`:

```bash
fly proxy 8080:80 -a jk-lago-front
open http://localhost:8080
```

Or wire the `api-gateway` at a private route (`/admin/lago/*`) — see
`api-gateway` repo.

## Rebuild from scratch

If the Fly org is wiped or you want a green-field environment:

1. **Take a Postgres dump** (skip if org is already gone):
   ```bash
   fly mpg backup create jk-lago-pg
   fly mpg backup download jk-lago-pg --latest -o ./lago-pg-backup.sql
   ```
2. **Destroy old apps** (if they exist):
   ```bash
   for app in jk-lago-api jk-lago-worker jk-lago-front; do
     fly apps destroy -y "$app" 2>/dev/null || true
   done
   fly mpg destroy jk-lago-pg 2>/dev/null || true
   fly redis destroy jk-lago-redis 2>/dev/null || true
   ```
3. **Re-run bootstrap** — it will regenerate secrets by default:
   ```bash
   FLY_ORG=jedi-knights ./scripts/lago-bootstrap.sh
   ```
4. **Deploy** (same three `fly deploy` commands as first-time).
5. **Restore Postgres dump** (if applicable):
   ```bash
   fly mpg import jk-lago-pg --file ./lago-pg-backup.sql
   ```
6. **Verify**: front reachable via `fly proxy`, api `/health` returns 200,
   worker logs show Sidekiq boot.

## Common operations

### View logs

```bash
fly logs -a jk-lago-api
fly logs -a jk-lago-worker
```

### Trigger a Postgres backup

Automated daily backups are on by default. Force one:

```bash
fly mpg backup create jk-lago-pg
fly mpg backup list jk-lago-pg
```

### Rotate the shared Lago secrets

```bash
./scripts/lago-bootstrap.sh --force-secrets
fly deploy -c fly.lago-api.toml
fly deploy -c fly.lago-worker.toml
```

**Caveat:** rotating `LAGO_ENCRYPTION_PRIMARY_KEY` invalidates data encrypted
under the old key. Rotate only during a maintenance window with a re-encrypt
pass first.

### Scale

```bash
fly scale count 2 -a jk-lago-api        # api is stateless behind Postgres
fly scale count 1 -a jk-lago-worker     # worker: Sidekiq handles multi-instance
fly scale vm shared-cpu-2x -a jk-lago-api  # bump memory/CPU if lag grows
```

## Troubleshooting

| Symptom                                | Likely cause                                    | Fix                                                        |
|----------------------------------------|-------------------------------------------------|------------------------------------------------------------|
| API `/health` returns 502              | DB migration never ran                          | `fly ssh console -a jk-lago-api -C 'bundle exec rails db:migrate'` |
| Front loads but shows "Network error"  | `API_URL` in `fly.lago-front.toml` mismatched   | Verify `jk-lago-api.internal:3000` resolves from front     |
| Worker logs "Redis::CannotConnectError"| `REDIS_URL` not attached                        | `fly redis attach jk-lago-redis -a jk-lago-worker`         |
| Invoices missing PDFs                  | `LAGO_DISABLE_PDF_GENERATION=true`              | Set to `false`, redeploy api                               |
| `SECRET_KEY_BASE` mismatch between apps| Bootstrap ran twice without `--force-secrets`   | Re-run with `--force-secrets`, redeploy both               |

## What's not in this runbook

- **Gateway routing to the admin UI** — lives in `api-gateway` repo.
- **Stripe wiring inside Lago** — covered by Epic 2 (#139).
- **Metering pipeline** — Epic 3+ (`jk-metering` repo).
