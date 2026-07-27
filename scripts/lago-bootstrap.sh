#!/usr/bin/env bash
# Bootstrap Fly.io infrastructure for self-hosted Lago (E1-S1 / issue #149).
#
# Idempotent: each step checks state before mutating. Safe to re-run.
# Requires: flyctl >=0.3, openssl, jq, an authenticated Fly org (FLY_ORG env var).
#
# Usage:
#   FLY_ORG=jedi-knights ./scripts/lago-bootstrap.sh [--region iad] [--dry-run]
#
# What it does, in order:
#   1. Creates three Fly apps: jk-lago-api, jk-lago-front, jk-lago-worker
#   2. Provisions Managed Postgres and attaches to api + worker (DATABASE_URL)
#   3. Provisions Upstash Redis and attaches to api + worker (REDIS_URL)
#   4. Generates and sets SECRET_KEY_BASE, LAGO_RSA_PRIVATE_KEY, and the
#      three LAGO_ENCRYPTION_* secrets on api + worker (identical values)
#   5. Prints the private hostnames + next-step deploy commands
#
# What it deliberately does NOT do:
#   - Run `fly deploy` — deployment is a separate, reviewed step (see runbook)
#   - Rotate secrets on re-run — set --force-secrets to override
#   - Create backups schedules — Managed Postgres has daily backups by default

set -euo pipefail

REGION="${REGION:-iad}"
FLY_ORG="${FLY_ORG:?FLY_ORG must be set (e.g. FLY_ORG=jedi-knights)}"
DRY_RUN=0
FORCE_SECRETS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --region)         REGION="$2"; shift 2 ;;
    --dry-run)        DRY_RUN=1; shift ;;
    --force-secrets)  FORCE_SECRETS=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

APPS=(jk-lago-api jk-lago-front jk-lago-worker)
PG_APP="jk-lago-pg"
REDIS_NAME="jk-lago-redis"

log()  { printf '[bootstrap] %s\n' "$*"; }
run()  { if [[ $DRY_RUN -eq 1 ]]; then echo "  DRY: $*"; else eval "$*"; fi; }

# 1. Create apps ---------------------------------------------------------------
for app in "${APPS[@]}"; do
  if fly apps list --json | jq -e --arg n "$app" '.[] | select(.Name==$n)' >/dev/null; then
    log "app $app already exists — skipping create"
  else
    log "creating app $app in org $FLY_ORG"
    run "fly apps create --org '$FLY_ORG' --name '$app'"
  fi
done

# 2. Postgres ------------------------------------------------------------------
if fly mpg list --org "$FLY_ORG" --json | jq -e --arg n "$PG_APP" '.[] | select(.name==$n)' >/dev/null; then
  log "managed postgres $PG_APP already exists — skipping create"
else
  log "creating managed postgres cluster $PG_APP"
  run "fly mpg create --org '$FLY_ORG' --name '$PG_APP' --region '$REGION' --plan basic"
fi

for app in jk-lago-api jk-lago-worker; do
  if fly secrets list -a "$app" --json | jq -e '.[] | select(.Name=="DATABASE_URL")' >/dev/null; then
    log "$app already has DATABASE_URL — skipping attach"
  else
    log "attaching $PG_APP to $app (sets DATABASE_URL)"
    run "fly mpg attach '$PG_APP' -a '$app'"
  fi
done

# 3. Redis ---------------------------------------------------------------------
if fly redis list --json | jq -e --arg n "$REDIS_NAME" '.[] | select(.Name==$n)' >/dev/null; then
  log "redis $REDIS_NAME already exists — skipping create"
else
  log "creating upstash redis $REDIS_NAME"
  run "fly redis create --org '$FLY_ORG' --name '$REDIS_NAME' --region '$REGION' --no-replicas --plan free"
fi

for app in jk-lago-api jk-lago-worker; do
  if fly secrets list -a "$app" --json | jq -e '.[] | select(.Name=="REDIS_URL")' >/dev/null; then
    log "$app already has REDIS_URL — skipping attach"
  else
    log "attaching $REDIS_NAME to $app (sets REDIS_URL)"
    run "fly redis attach '$REDIS_NAME' -a '$app'"
  fi
done

# 4. Secrets -------------------------------------------------------------------
# Generate once; set identical values on api + worker.
have_secret() {
  local app="$1" name="$2"
  fly secrets list -a "$app" --json | jq -e --arg n "$name" '.[] | select(.Name==$n)' >/dev/null
}

need_generate=0
for name in SECRET_KEY_BASE LAGO_RSA_PRIVATE_KEY LAGO_ENCRYPTION_KEY_SALT \
            LAGO_ENCRYPTION_DETERMINISTIC_KEY LAGO_ENCRYPTION_PRIMARY_KEY; do
  if ! have_secret jk-lago-api "$name" || [[ $FORCE_SECRETS -eq 1 ]]; then
    need_generate=1
  fi
done

if [[ $need_generate -eq 1 ]]; then
  log "generating shared secrets (api + worker)"
  SECRET_KEY_BASE="$(openssl rand -hex 64)"
  LAGO_RSA_PRIVATE_KEY="$(openssl genrsa 2048 2>/dev/null | base64 | tr -d '\n')"
  LAGO_ENCRYPTION_KEY_SALT="$(openssl rand -hex 32)"
  LAGO_ENCRYPTION_DETERMINISTIC_KEY="$(openssl rand -hex 32)"
  LAGO_ENCRYPTION_PRIMARY_KEY="$(openssl rand -hex 32)"

  for app in jk-lago-api jk-lago-worker; do
    log "setting secrets on $app"
    run "fly secrets set -a '$app' --stage \
      SECRET_KEY_BASE='$SECRET_KEY_BASE' \
      LAGO_RSA_PRIVATE_KEY='$LAGO_RSA_PRIVATE_KEY' \
      LAGO_ENCRYPTION_KEY_SALT='$LAGO_ENCRYPTION_KEY_SALT' \
      LAGO_ENCRYPTION_DETERMINISTIC_KEY='$LAGO_ENCRYPTION_DETERMINISTIC_KEY' \
      LAGO_ENCRYPTION_PRIMARY_KEY='$LAGO_ENCRYPTION_PRIMARY_KEY'"
  done
  unset SECRET_KEY_BASE LAGO_RSA_PRIVATE_KEY LAGO_ENCRYPTION_KEY_SALT \
        LAGO_ENCRYPTION_DETERMINISTIC_KEY LAGO_ENCRYPTION_PRIMARY_KEY
else
  log "all shared secrets already set — pass --force-secrets to rotate"
fi

# 5. Next steps ----------------------------------------------------------------
cat <<'NEXT'

[bootstrap] complete. Next steps (see docs/lago-runbook.md for detail):

  fly deploy -c fly.lago-api.toml
  fly deploy -c fly.lago-worker.toml
  fly deploy -c fly.lago-front.toml

Then run the first-time DB migration inside the api container:
  fly ssh console -a jk-lago-api -C 'bundle exec rails db:migrate'

Create the initial admin user via Lago's signup API (see runbook §Initial admin).
NEXT
