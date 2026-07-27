#!/usr/bin/env bash
# Smoke test for the mcp_tool_calls billable metric (E2-S3 / #153).
#
# Creates a temporary customer, subscribes to touchline-coach, fires two
# events (one per priced tool_id), then reads the invoice preview and
# asserts the two line-item amounts match the expected per-tool rates.
#
# Requires env vars:
#   LAGO_API_KEY, LAGO_API_URL   (source infra/stripe/secrets.env)
#
# Optional:
#   PLAN_CODE   defaults to touchline-coach
#   EVENT_COUNT_NWSL   defaults to 100 (100 * $0.002 = $0.20 = 20 cents)
#   EVENT_COUNT_NCAA   defaults to  50 ( 50 * $0.010 = $0.50 = 50 cents)
#
# Usage (from repo root):
#   set -a; source infra/stripe/secrets.env; set +a
#   ./infra/lago/metrics/smoke-test.sh
#
# Exit codes:
#   0  invoice preview shows expected per-tool amounts
#   2  Lago unreachable
#   3  metric or plan missing (run apply.sh first)
#   4  customer / subscription create failed
#   5  event ingest failed
#   6  invoice preview did not include the expected line items
#   7  line-item amount mismatch

set -euo pipefail

: "${LAGO_API_KEY:?set LAGO_API_KEY}"
: "${LAGO_API_URL:?set LAGO_API_URL}"

PLAN_CODE="${PLAN_CODE:-touchline-coach}"
EVENT_COUNT_NWSL="${EVENT_COUNT_NWSL:-100}"
EVENT_COUNT_NCAA="${EVENT_COUNT_NCAA:-50}"
CUSTOMER_CODE="metric_smoke_$(date +%s)"

# Expected charges in cents (Lago returns amount_cents on invoice previews)
expected_nwsl_cents=$(( EVENT_COUNT_NWSL * 2 / 10 ))     # 100 * 0.002 * 100c = 20
expected_ncaa_cents=$(( EVENT_COUNT_NCAA * 10 / 10 ))    # 50 * 0.01 * 100c = 50

log()  { printf '[metric-smoke] %s\n' "$*"; }
fail() { log "FAIL: $1"; exit "$2"; }

# --- reachability + prerequisites --------------------------------------------

ping=$(curl -sS -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $LAGO_API_KEY" \
  "$LAGO_API_URL/api/v1/organizations/current" || true)
[[ "$ping" == "200" ]] || fail "Lago unreachable ($ping)" 2

status=$(curl -sS -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $LAGO_API_KEY" \
  "$LAGO_API_URL/api/v1/billable_metrics/mcp_tool_calls")
[[ "$status" == "200" ]] || fail "mcp_tool_calls metric missing — run infra/lago/metrics/apply.sh first" 3

status=$(curl -sS -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $LAGO_API_KEY" \
  "$LAGO_API_URL/api/v1/plans/$PLAN_CODE")
[[ "$status" == "200" ]] || fail "plan $PLAN_CODE missing — run infra/lago/plans/apply.sh first" 3

# --- customer + subscription --------------------------------------------------

log "creating customer $CUSTOMER_CODE"
resp=$(curl -sS -o /tmp/lago-cust.json -w "%{http_code}" \
  -X POST "$LAGO_API_URL/api/v1/customers" \
  -H "Authorization: Bearer $LAGO_API_KEY" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg c "$CUSTOMER_CODE" \
        '{customer: {external_id: $c, name: "Metric smoke", email: "smoke+\($c)@jedi-knights.dev"}}')")
[[ "$resp" == "200" || "$resp" == "201" ]] \
  || { cat /tmp/lago-cust.json; fail "customer create $resp" 4; }

sub_ext_id="metric_smoke_sub_$CUSTOMER_CODE"
log "subscribing to $PLAN_CODE"
resp=$(curl -sS -o /tmp/lago-sub.json -w "%{http_code}" \
  -X POST "$LAGO_API_URL/api/v1/subscriptions" \
  -H "Authorization: Bearer $LAGO_API_KEY" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg c "$CUSTOMER_CODE" --arg p "$PLAN_CODE" --arg s "$sub_ext_id" \
        '{subscription: {external_customer_id: $c, plan_code: $p, external_id: $s}}')")
[[ "$resp" == "200" || "$resp" == "201" ]] \
  || { cat /tmp/lago-sub.json; fail "subscription create $resp" 4; }

# --- ingest events ------------------------------------------------------------

send_events() {
  local tool_id="$1" count="$2"
  log "sending $count events for tool_id=$tool_id"
  local i
  for ((i=0; i<count; i++)); do
    local tx="ev_${CUSTOMER_CODE}_${tool_id//[:\/]/_}_$i"
    resp=$(curl -sS -o /tmp/lago-ev.json -w "%{http_code}" \
      -X POST "$LAGO_API_URL/api/v1/events" \
      -H "Authorization: Bearer $LAGO_API_KEY" \
      -H "Content-Type: application/json" \
      -d "$(jq -n --arg c "$CUSTOMER_CODE" --arg tx "$tx" --arg tid "$tool_id" \
            '{event: {transaction_id: $tx, external_subscription_id: $c,
                      code: "mcp_tool_calls",
                      properties: {tool_id: $tid}}}')" || true)
    [[ "$resp" == "200" || "$resp" == "201" ]] \
      || { cat /tmp/lago-ev.json; fail "event $tx returned $resp" 5; }
  done
}

send_events "jk-mcp-nwsl:get_standings" "$EVENT_COUNT_NWSL"
send_events "jk-mcp-ncaa:get_rpi"       "$EVENT_COUNT_NCAA"

# Lago aggregates asynchronously; give it a beat before invoice preview.
sleep 5

# --- invoice preview ----------------------------------------------------------

log "fetching invoice preview for $CUSTOMER_CODE"
resp=$(curl -sS -o /tmp/lago-preview.json -w "%{http_code}" \
  -H "Authorization: Bearer $LAGO_API_KEY" \
  "$LAGO_API_URL/api/v1/invoices/preview?external_customer_id=$CUSTOMER_CODE")
[[ "$resp" == "200" ]] || { cat /tmp/lago-preview.json; fail "invoice preview $resp" 6; }

nwsl_cents=$(jq -r '[.invoice.fees[]? | select(.invoice_display_name == "NWSL get_standings") | .amount_cents] | add // 0' /tmp/lago-preview.json)
ncaa_cents=$(jq -r '[.invoice.fees[]? | select(.invoice_display_name == "NCAA get_rpi") | .amount_cents] | add // 0' /tmp/lago-preview.json)

log "invoice preview: NWSL=$nwsl_cents cents, NCAA=$ncaa_cents cents"
log "expected:        NWSL=$expected_nwsl_cents cents, NCAA=$expected_ncaa_cents cents"

if [[ "$nwsl_cents" -ne "$expected_nwsl_cents" ]]; then
  fail "NWSL charge $nwsl_cents != expected $expected_nwsl_cents" 7
fi
if [[ "$ncaa_cents" -ne "$expected_ncaa_cents" ]]; then
  fail "NCAA charge $ncaa_cents != expected $expected_ncaa_cents" 7
fi

log "PASS: per-tool pricing applied correctly"
echo
echo "Cleanup:"
echo "  curl -X DELETE -H \"Authorization: Bearer \$LAGO_API_KEY\" \\"
echo "    \"\$LAGO_API_URL/api/v1/customers/$CUSTOMER_CODE\""
