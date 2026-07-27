# Lago on Fly.io — Day-2 Runbook

Ongoing operational tasks for the self-hosted Lago deployment. For first-time
deploy, rebuild-from-scratch, or the post-deploy admin-UI checklist, see
[`README.md`](./README.md).

## Common operations

### View logs

```bash
fly logs -a jk-lago-api
fly logs -a jk-lago-worker
fly logs -a jk-lago-front
```

Filter Sidekiq errors:

```bash
fly logs -a jk-lago-worker | grep -Ei 'error|fatal|retrying'
```

### Trigger a Postgres backup

Automated daily backups are on by default. Force one:

```bash
fly mpg backup create jk-lago-pg
fly mpg backup list jk-lago-pg
```

Download the latest to disk:

```bash
fly mpg backup download jk-lago-pg --latest -o ./lago-pg-backup.sql
```

### Rotate the shared Lago secrets

```bash
./infra/lago/bootstrap.sh --force-secrets
fly deploy -c infra/lago/fly.lago-api.toml
fly deploy -c infra/lago/fly.lago-worker.toml
```

**Caveat:** rotating `LAGO_ENCRYPTION_PRIMARY_KEY` invalidates data
encrypted under the old key. Rotate only during a maintenance window with a
re-encrypt pass first (Rails runner: `EncryptionKeyRotator.new.run!` or
equivalent).

### Scale

```bash
fly scale count 2 -a jk-lago-api        # api is stateless behind Postgres
fly scale count 1 -a jk-lago-worker     # worker: Sidekiq handles multi-instance
fly scale vm shared-cpu-2x -a jk-lago-api  # bump memory/CPU if lag grows
```

Watch the worker's Sidekiq lag before adding replicas:

```bash
fly ssh console -a jk-lago-worker -C 'bundle exec sidekiq-status'
```

### Reset the admin password

If an operator loses access:

```bash
fly ssh console -a jk-lago-api -C 'bundle exec rails runner "
  u = User.find_by!(email: %q(ops@jedi-knights.dev))
  new_pw = SecureRandom.base64(24)
  u.update!(password: new_pw)
  puts new_pw
"'
```

Save the printed password to 1Password/Bitwarden, then rotate again from
the UI once the operator is back in.

## Troubleshooting

| Symptom                                | Likely cause                                    | Fix                                                                    |
|----------------------------------------|-------------------------------------------------|------------------------------------------------------------------------|
| API `/health` returns 502              | DB migration never ran                          | `fly ssh console -a jk-lago-api -C 'bundle exec rails db:migrate'`     |
| Front loads but shows "Network error"  | `API_URL` in `fly.lago-front.toml` mismatched   | Verify `jk-lago-api.internal:3000` resolves from front                 |
| Worker logs "Redis::CannotConnectError"| `REDIS_URL` not attached                        | `fly redis attach jk-lago-redis -a jk-lago-worker`                     |
| Invoices missing PDFs                  | `LAGO_DISABLE_PDF_GENERATION=true`              | Set to `false` in `fly.lago-api.toml`, redeploy api                    |
| `SECRET_KEY_BASE` mismatch between apps| Bootstrap ran twice without `--force-secrets`   | Re-run with `--force-secrets`, redeploy both                           |
| API 401s valid API keys                | Encryption keys rotated without re-encrypt pass | Restore keys from secret manager, or re-encrypt then rotate            |
| Sidekiq lag > 5 min                    | Worker VM undersized                            | `fly scale vm shared-cpu-2x -a jk-lago-worker`, or `fly scale count 2` |
| Postgres near disk limit               | Backups not being pruned                        | `fly mpg backup prune jk-lago-pg --keep 7`                             |

## What's not in this runbook

- **Gateway routing to the admin UI** — lives in `api-gateway` repo.
- **Stripe wiring inside Lago** — covered by Epic 2 (#139).
- **Metering pipeline** — Epic 3+ (`jk-metering` repo).
