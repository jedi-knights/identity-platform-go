#!/usr/bin/env bash
# Apply the Touchline entitlements catalog seed to Postgres (E3-S3 / #156).
#
# Idempotent — the seed SQL uses ON CONFLICT upserts throughout, so
# re-running is safe and non-destructive. Run after the schema migration
# (000001_create_entitlements_schema) has been applied.
#
# Requires:
#   ENTITLEMENTS_DATABASE_URL   — Postgres connection string
#   psql (from postgresql-client)
#
# Usage (from repo root):
#   export ENTITLEMENTS_DATABASE_URL="postgres://user:pass@host:5432/entitlements"
#   ./services/entitlements-service/seeds/apply.sh [--dry-run]
#
# Exit codes:
#   0  seed applied (or no-op on re-run)
#   2  Postgres unreachable
#   3  seed SQL raised an error
#   4  post-seed row count assertions failed

set -euo pipefail

: "${ENTITLEMENTS_DATABASE_URL:?set ENTITLEMENTS_DATABASE_URL}"

SEED_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEED_FILE="$SEED_DIR/touchline-catalog.sql"

DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

log() { printf '[seed] %s\n' "$*"; }

log "checking Postgres reachability"
if ! psql "$ENTITLEMENTS_DATABASE_URL" -c 'SELECT 1' >/dev/null 2>&1; then
  log "Postgres unreachable — check ENTITLEMENTS_DATABASE_URL"
  exit 2
fi

log "verifying schema is present (000001 migration applied)"
missing=$(psql "$ENTITLEMENTS_DATABASE_URL" -tA -c "
  SELECT string_agg(t, ', ')
  FROM (VALUES ('accounts'),('account_seats'),('resources'),('bundles'),
               ('bundle_resources'),('plans'),('plan_bundles'),('account_plans')) v(t)
  WHERE NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema='public' AND table_name=v.t
  );")
if [[ -n "$missing" ]]; then
  log "schema missing tables: $missing — run 000001 migration first"
  exit 3
fi

if [[ $DRY_RUN -eq 1 ]]; then
  log "--dry-run: skipping seed apply. Would psql -f $SEED_FILE"
else
  log "applying seed: $SEED_FILE"
  if ! psql "$ENTITLEMENTS_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$SEED_FILE" >/tmp/seed-out 2>&1; then
    log "seed failed:"
    cat /tmp/seed-out
    exit 3
  fi
fi

log "verifying post-seed row counts"
counts=$(psql "$ENTITLEMENTS_DATABASE_URL" -tA -F$'\t' -c "
  SELECT
    (SELECT count(*) FROM resources),
    (SELECT count(*) FROM bundles),
    (SELECT count(*) FROM bundle_resources),
    (SELECT count(*) FROM plans),
    (SELECT count(*) FROM plan_bundles);")
IFS=$'\t' read -r n_res n_bun n_br n_plan n_pb <<< "$counts"

log "resources=$n_res bundles=$n_bun bundle_resources=$n_br plans=$n_plan plan_bundles=$n_pb"

# Minimums — the seed defines at least this many rows. Actual counts may be
# higher if downstream operators added their own; the assertion is >=.
ok=1
check() {
  local name="$1" actual="$2" min="$3"
  if [[ "$actual" -lt "$min" ]]; then
    log "  $name: $actual < expected minimum $min"
    ok=0
  fi
}
check resources        "$n_res"  25
check bundles          "$n_bun"  6
check bundle_resources "$n_br"   37
check plans            "$n_plan" 3
check plan_bundles     "$n_pb"   7

if [[ $ok -ne 1 ]]; then
  log "assertion failure — seed appears incomplete"
  exit 4
fi

log "seed applied and verified"
