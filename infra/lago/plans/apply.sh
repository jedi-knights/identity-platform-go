#!/usr/bin/env bash
# Apply the Touchline plan catalog to a running Lago instance (E2-S2 / #152).
#
# For each *.json in this directory:
#   - GET /api/v1/plans/<code>
#   - if 404, POST /api/v1/plans        (create)
#   - if 200, PUT  /api/v1/plans/<code> (update — Lago merges by code)
#
# Idempotent. Safe to re-run. Diff-friendly output: prints created/updated/
# unchanged per plan.
#
# Requires env vars:
#   LAGO_API_KEY  — from Lago admin UI → Developers → API keys
#   LAGO_API_URL  — e.g. http://localhost:3000 via `fly proxy`
#
# Usage (from repo root):
#   set -a; source infra/stripe/secrets.env; set +a
#   ./infra/lago/plans/apply.sh [--dry-run]
#
# Exit codes:
#   0  all plans applied
#   2  Lago unreachable
#   3  a plan file failed to apply (Lago returned non-2xx)

set -euo pipefail

: "${LAGO_API_KEY:?set LAGO_API_KEY (source infra/stripe/secrets.env)}"
: "${LAGO_API_URL:?set LAGO_API_URL}"

PLANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

log() { printf '[plans] %s\n' "$*"; }

log "checking Lago reachability at $LAGO_API_URL"
ping=$(curl -sS -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $LAGO_API_KEY" \
  "$LAGO_API_URL/api/v1/organizations/current" || true)
[[ "$ping" == "200" ]] || { log "Lago returned $ping — is the tunnel up?"; exit 2; }

exit_code=0
for f in "$PLANS_DIR"/*.json; do
  [[ -e "$f" ]] || { log "no plan files in $PLANS_DIR"; break; }
  code=$(jq -r '.plan.code' "$f")
  name=$(jq -r '.plan.name' "$f")
  [[ -n "$code" && "$code" != "null" ]] || { log "SKIP $f: missing .plan.code"; exit_code=3; continue; }

  status=$(curl -sS -o /tmp/lago-plan.json -w "%{http_code}" \
    -H "Authorization: Bearer $LAGO_API_KEY" \
    "$LAGO_API_URL/api/v1/plans/$code" || true)

  case "$status" in
    200)
      # Compare — Lago echoes the persisted plan; diff on amount_cents,
      # trial_period, name, and metadata is enough for E2-S2 scope.
      current=$(jq -c '{name: .plan.name, amount_cents: .plan.amount_cents,
                        trial_period: .plan.trial_period,
                        metadata: (.plan.metadata // {})}' /tmp/lago-plan.json)
      desired=$(jq -c '{name: .plan.name, amount_cents: .plan.amount_cents,
                        trial_period: .plan.trial_period,
                        metadata: (.plan.metadata // {})}' "$f")
      if [[ "$current" == "$desired" ]]; then
        log "unchanged: $code ($name)"
        continue
      fi
      log "updating:  $code ($name)"
      if [[ $DRY_RUN -eq 1 ]]; then continue; fi
      resp=$(curl -sS -o /tmp/lago-put.json -w "%{http_code}" \
        -X PUT "$LAGO_API_URL/api/v1/plans/$code" \
        -H "Authorization: Bearer $LAGO_API_KEY" \
        -H "Content-Type: application/json" \
        -d @"$f")
      [[ "$resp" == "200" ]] || { log "  FAIL: PUT returned $resp"; cat /tmp/lago-put.json; exit_code=3; }
      ;;
    404)
      log "creating:  $code ($name)"
      if [[ $DRY_RUN -eq 1 ]]; then continue; fi
      resp=$(curl -sS -o /tmp/lago-post.json -w "%{http_code}" \
        -X POST "$LAGO_API_URL/api/v1/plans" \
        -H "Authorization: Bearer $LAGO_API_KEY" \
        -H "Content-Type: application/json" \
        -d @"$f")
      [[ "$resp" == "200" || "$resp" == "201" ]] \
        || { log "  FAIL: POST returned $resp"; cat /tmp/lago-post.json; exit_code=3; }
      ;;
    *)
      log "unexpected status $status for $code:"
      cat /tmp/lago-plan.json
      exit_code=3
      ;;
  esac
done

if [[ $exit_code -eq 0 ]]; then
  log "all plans applied"
else
  log "one or more plans failed — see output above"
fi
exit $exit_code
