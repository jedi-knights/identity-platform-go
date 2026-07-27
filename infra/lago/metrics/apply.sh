#!/usr/bin/env bash
# Apply Lago billable metric definitions from JSON files (E2-S3 / #153).
#
# For each *.json in this directory:
#   - GET /api/v1/billable_metrics/<code>
#   - if 404, POST /api/v1/billable_metrics        (create)
#   - if 200, PUT  /api/v1/billable_metrics/<code> (update)
#
# Metrics must be applied BEFORE plans that reference them (plans reference
# metrics by code and Lago validates the code exists on plan create).
#
# Requires env vars:
#   LAGO_API_KEY  — from Lago admin UI → Developers → API keys
#   LAGO_API_URL  — e.g. http://localhost:3000 via `fly proxy`
#
# Usage (from repo root):
#   set -a; source infra/stripe/secrets.env; set +a
#   ./infra/lago/metrics/apply.sh [--dry-run]
#
# Exit codes:
#   0  all metrics applied
#   2  Lago unreachable
#   3  a metric file failed to apply

set -euo pipefail

: "${LAGO_API_KEY:?set LAGO_API_KEY (source infra/stripe/secrets.env)}"
: "${LAGO_API_URL:?set LAGO_API_URL}"

METRICS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

log() { printf '[metrics] %s\n' "$*"; }

log "checking Lago reachability at $LAGO_API_URL"
ping=$(curl -sS -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $LAGO_API_KEY" \
  "$LAGO_API_URL/api/v1/organizations/current" || true)
[[ "$ping" == "200" ]] || { log "Lago returned $ping — is the tunnel up?"; exit 2; }

exit_code=0
for f in "$METRICS_DIR"/*.json; do
  [[ -e "$f" ]] || { log "no metric files in $METRICS_DIR"; break; }
  code=$(jq -r '.billable_metric.code' "$f")
  name=$(jq -r '.billable_metric.name' "$f")
  [[ -n "$code" && "$code" != "null" ]] || { log "SKIP $f: missing .billable_metric.code"; exit_code=3; continue; }

  status=$(curl -sS -o /tmp/lago-metric.json -w "%{http_code}" \
    -H "Authorization: Bearer $LAGO_API_KEY" \
    "$LAGO_API_URL/api/v1/billable_metrics/$code" || true)

  case "$status" in
    200)
      current=$(jq -cS '{name: .billable_metric.name,
                          aggregation_type: .billable_metric.aggregation_type,
                          field_name: .billable_metric.field_name,
                          recurring: .billable_metric.recurring,
                          filters: (.billable_metric.filters // [])}' /tmp/lago-metric.json)
      desired=$(jq -cS '{name: .billable_metric.name,
                          aggregation_type: .billable_metric.aggregation_type,
                          field_name: .billable_metric.field_name,
                          recurring: .billable_metric.recurring,
                          filters: (.billable_metric.filters // [])}' "$f")
      if [[ "$current" == "$desired" ]]; then
        log "unchanged: $code ($name)"
        continue
      fi
      log "updating:  $code ($name)"
      if [[ $DRY_RUN -eq 1 ]]; then continue; fi
      resp=$(curl -sS -o /tmp/lago-put.json -w "%{http_code}" \
        -X PUT "$LAGO_API_URL/api/v1/billable_metrics/$code" \
        -H "Authorization: Bearer $LAGO_API_KEY" \
        -H "Content-Type: application/json" \
        -d @"$f")
      [[ "$resp" == "200" ]] || { log "  FAIL: PUT returned $resp"; cat /tmp/lago-put.json; exit_code=3; }
      ;;
    404)
      log "creating:  $code ($name)"
      if [[ $DRY_RUN -eq 1 ]]; then continue; fi
      resp=$(curl -sS -o /tmp/lago-post.json -w "%{http_code}" \
        -X POST "$LAGO_API_URL/api/v1/billable_metrics" \
        -H "Authorization: Bearer $LAGO_API_KEY" \
        -H "Content-Type: application/json" \
        -d @"$f")
      [[ "$resp" == "200" || "$resp" == "201" ]] \
        || { log "  FAIL: POST returned $resp"; cat /tmp/lago-post.json; exit_code=3; }
      ;;
    *)
      log "unexpected status $status for $code:"
      cat /tmp/lago-metric.json
      exit_code=3
      ;;
  esac
done

if [[ $exit_code -eq 0 ]]; then
  log "all metrics applied"
else
  log "one or more metrics failed — see output above"
fi
exit $exit_code
