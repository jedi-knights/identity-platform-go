# Lago on Fly.io — Infrastructure

Everything needed to stand up (or rebuild) self-hosted Lago on Fly.io lives in
this directory. Rebuild-from-scratch on a new Fly org is a scripted operation
that fits in a **60-minute budget** (see [§Rebuild time budget](#rebuild-time-budget)).

- [`bootstrap.sh`](./bootstrap.sh) — idempotent Fly org provisioning
- [`fly.lago-api.toml`](./fly.lago-api.toml) — API service (Puma, port 3000)
- [`fly.lago-front.toml`](./fly.lago-front.toml) — Admin UI (nginx SPA, port 80)
- [`fly.lago-worker.toml`](./fly.lago-worker.toml) — Sidekiq worker (no HTTP)
- [`secrets.env.example`](./secrets.env.example) — template for the five shared Lago secrets
- [`runbook.md`](./runbook.md) — day-2 operations: logs, backups, rotation, scale, troubleshooting

**Related issues:** [#138](https://github.com/jedi-knights/identity-platform-go/issues/138) (Epic 1), [#149](https://github.com/jedi-knights/identity-platform-go/issues/149) (E1-S1), [#150](https://github.com/jedi-knights/identity-platform-go/issues/150) (E1-S2).

## Prerequisites

- `flyctl` >= 0.3, authenticated (`fly auth login`)
- `openssl`, `jq`, `bash` >= 4
- Membership in the target Fly org (defaults to `jedi-knights`)
- Read access to this repo

## Topology

| Fly app         | Image                | Ports  | Purpose                              |
|-----------------|----------------------|--------|--------------------------------------|
| `jk-lago-api`   | `getlago/api:v1`     | 3000   | Lago REST API (Rails + Puma)         |
| `jk-lago-front` | `getlago/front:v1`   | 80     | Admin UI (React SPA, nginx-served)   |
| `jk-lago-worker`| `getlago/api:v1`     | —      | Sidekiq worker for background jobs   |
| `jk-lago-pg`    | Managed Postgres     | —      | Shared DB for api + worker (daily backups)  |
| `jk-lago-redis` | Upstash Redis        | —      | Sidekiq queue + Lago cache           |

All apps are **private** (no public IPv4). Reachable via Fly's `.internal`
6PN network. Admin UI is exposed to operators via `fly proxy` (see below)
or via the `api-gateway` repo (separate).

## Deploy sequence

The full sequence, copy-pasteable end-to-end:

```bash
# 0. Environment
export FLY_ORG=jedi-knights
cd $(git rev-parse --show-toplevel)

# 1. Bootstrap: create apps, Postgres, Redis, and set shared secrets.
#    Idempotent — safe to re-run.
./infra/lago/bootstrap.sh --region iad

# 2. Deploy the three services. API first (schema-owner), worker second
#    (shares codebase + secrets), front last (needs api reachable).
fly deploy -c infra/lago/fly.lago-api.toml
fly deploy -c infra/lago/fly.lago-worker.toml
fly deploy -c infra/lago/fly.lago-front.toml

# 3. First-time DB migration (once per environment).
fly ssh console -a jk-lago-api -C 'bundle exec rails db:migrate'
fly ssh console -a jk-lago-api -C 'bundle exec rails db:seed'

# 4. Verify.
fly status -a jk-lago-api
fly status -a jk-lago-worker
fly status -a jk-lago-front
```

At this point three green apps are running with no admin user yet.
Continue with [§Post-deploy admin-UI steps](#post-deploy-admin-ui-steps).

## Post-deploy admin-UI steps

These are the manual steps the operator performs in Lago's admin UI (or via
the Rails console) after the three services are up. Everything below happens
**inside a `fly proxy` tunnel** — the front app has no public IP.

Open the tunnel and the browser:

```bash
fly proxy 8080:80 -a jk-lago-front &
open http://localhost:8080
```

Then, in order:

1. **Bootstrap the first admin** (Rails runner, one-shot):
   ```bash
   fly secrets set --stage -a jk-lago-api \
     BOOTSTRAP_ADMIN_EMAIL='ops@jedi-knights.dev' \
     BOOTSTRAP_ADMIN_PASSWORD="$(openssl rand -base64 24)"
   fly deploy -c infra/lago/fly.lago-api.toml   # apply staged secrets
   fly ssh console -a jk-lago-api -C 'bundle exec rails runner "
     org = Organization.create!(name: %q(Jedi Knights))
     User.create!(
       email: ENV.fetch(%q(BOOTSTRAP_ADMIN_EMAIL)),
       password: ENV.fetch(%q(BOOTSTRAP_ADMIN_PASSWORD)),
       organizations: [org]
     )"'
   fly secrets unset -a jk-lago-api BOOTSTRAP_ADMIN_EMAIL BOOTSTRAP_ADMIN_PASSWORD
   ```
   Save the generated password into 1Password/Bitwarden **before** unsetting.

2. **Log in** at http://localhost:8080 with the bootstrap credentials.

3. **Create a real operator user** under *Settings → Members → Invite member*,
   then log out and log back in as that user. Delete the `ops@` bootstrap user.

4. **Rotate the admin password** — Lago's default password policy is weak;
   set the operator user's password to a 24+ char passphrase.

5. **Generate an API key** — *Developers → API keys → Create*. Save into
   the platform's secret manager as `LAGO_API_KEY`. This is what
   downstream services (Stripe wiring, jk-metering) will use.

6. **Configure webhook signing** — *Developers → Webhooks*. Set the shared
   signing secret and the callback URL (the api-gateway path that fronts
   `jk-metering`'s webhook handler).

7. **Set the organization time zone and currency** — *Settings →
   Organization*. Default is UTC / USD; adjust if needed. Affects invoice
   period boundaries; **change once, do not change again after invoices
   have been generated**.

8. **Wire Stripe** — see [`../stripe/README.md`](../stripe/README.md) for the
   full sequence: create test-mode Stripe account → capture keys → run
   `wire-lago-connector.sh` → register the Stripe webhook endpoint → verify
   with `smoke-test.sh`. Track under [#151](https://github.com/jedi-knights/identity-platform-go/issues/151).

9. **Apply the billable metrics** — see
   [`metrics/README.md`](./metrics/README.md). Metrics must exist before
   plans that reference them:
   ```bash
   set -a; source infra/stripe/secrets.env; set +a
   ./infra/lago/metrics/apply.sh
   ```

10. **Apply the Touchline plan catalog** — see
    [`plans/README.md`](./plans/README.md). One command:
    ```bash
    ./infra/lago/plans/apply.sh
    ```
    Applies `touchline-free`, `touchline-coach`, `touchline-club` from the
    JSON files. Idempotent.

11. **Smoke-test the pipeline** — from the API key created in step 5:
   ```bash
   curl -H "Authorization: Bearer $LAGO_API_KEY" \
     https://jk-lago-api.internal:3000/api/v1/organizations
   ```
   Expected: 200 with the org JSON.

## Rebuild time budget

Rebuilding on a fresh Fly org — for example, after moving billing to a new
Fly account or after a disaster-recovery reprovision — fits in a
**60-minute budget** on a warm operator laptop. Phase timings, measured on
one dry run:

| Phase                                              | Elapsed | Cumulative |
|----------------------------------------------------|--------:|-----------:|
| `bootstrap.sh` — create apps, Postgres, Redis      |  ~6 min |     6 min  |
| `bootstrap.sh` — generate + set 5 shared secrets   |  ~1 min |     7 min  |
| `fly deploy -c fly.lago-api.toml`                  |  ~4 min |    11 min  |
| `fly deploy -c fly.lago-worker.toml`               |  ~3 min |    14 min  |
| `fly deploy -c fly.lago-front.toml`                |  ~3 min |    17 min  |
| First-time `db:migrate` + `db:seed`                |  ~2 min |    19 min  |
| Restore Postgres dump (skip on green-field)        |  ~8 min |    27 min  |
| Bootstrap admin + create operator user (UI steps)  |  ~5 min |    32 min  |
| Regenerate API key + configure webhook signing     |  ~3 min |    35 min  |
| Smoke test + spot-check invoices                   |  ~5 min |    40 min  |
| Slack / status-page announcement                   |  ~5 min |    45 min  |
| **Slack for unplanned troubleshooting**            | ~15 min |    60 min  |

Any phase that blows its budget triggers a stop-and-diagnose — see
[`runbook.md`](./runbook.md#troubleshooting) for the failure table. If the
total goes past 60 min, log the delta in the incident channel and update
this budget in the next PR.

## Rebuild-from-scratch commands

Full sequence — safe to run against an empty Fly org, destructive against
an existing one:

```bash
export FLY_ORG=jedi-knights

# (optional) Snapshot the outgoing environment first.
fly mpg backup create jk-lago-pg
fly mpg backup download jk-lago-pg --latest -o ./lago-pg-backup.sql

# Wipe (skip if org is already empty).
for app in jk-lago-api jk-lago-worker jk-lago-front; do
  fly apps destroy -y "$app" 2>/dev/null || true
done
fly mpg destroy jk-lago-pg 2>/dev/null || true
fly redis destroy jk-lago-redis 2>/dev/null || true

# Rebuild.
./infra/lago/bootstrap.sh --region iad --force-secrets
fly deploy -c infra/lago/fly.lago-api.toml
fly deploy -c infra/lago/fly.lago-worker.toml
fly deploy -c infra/lago/fly.lago-front.toml
fly ssh console -a jk-lago-api -C 'bundle exec rails db:migrate'

# Restore (skip on green-field).
fly mpg import jk-lago-pg --file ./lago-pg-backup.sql
```

Then run through [§Post-deploy admin-UI steps](#post-deploy-admin-ui-steps).

## Day-2 operations

Ongoing operational tasks — log tailing, backup management, secret rotation,
horizontal scaling, and the failure→fix table — live in
[`runbook.md`](./runbook.md).
