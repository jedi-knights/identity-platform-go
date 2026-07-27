#!/usr/bin/env bash
# End-to-end smoke test: Lago + Stripe test-mode connector (E2-S1 / issue #151).
#
# Drives a paid checkout via Lago's API, expects Stripe to create a customer +
# subscription, then confirms Lago received the webhook back. Verifies every
# link in the Stripe↔Lago chain.
#
# Requires env vars (source infra/stripe/secrets.env first):
#   STRIPE_SECRET_KEY  — sk_test_...
#   LAGO_API_KEY
#   LAGO_API_URL
#
# Optional:
#   PLAN_CODE          — a Lago plan code that exists in the org (defaults to
#                        `smoke_test_plan` — created on first run if missing).
#
# Usage (from repo root):
#   set -a; source infra/stripe/secrets.env; set +a
#   ./infra/stripe/smoke-test.sh
#
# Exit codes:
#   0  everything green
#   1  invalid env
#   2  Lago API unreachable
#   3  Stripe API unreachable
#   4  plan create/lookup failed
#   5  customer create failed
#   6  subscription create failed
#   7  Stripe did not receive the customer
#   8  Lago did not receive the webhook within timeout

set -euo pipefail

: "${STRIPE_SECRET_KEY:?set STRIPE_SECRET_KEY (source infra/stripe/secrets.env)}"
: "${LAGO_API_KEY:?set LAGO_API_KEY}"
: "${LAGO_API_URL:?set LAGO_API_URL}"

PLAN_CODE="${PLAN_CODE:-smoke_test_plan}"
CUSTOMER_CODE="smoke_test_$(date +%s)"
WEBHOOK_TIMEOUT="${WEBHOOK_TIMEOUT:-30}"  # seconds

if [[ "$STRIPE_SECRET_KEY" != sk_test_* ]]; then
  echo "refusing: STRIPE_SECRET_KEY is not test-mode" >&2
  exit 1
fi

log()  { printf '[smoke] %s\n' "$*"; }
fail() { log "FAIL: $*"; exit "$2"; }

# --- reachability -------------------------------------------------------------

log "checking Lago reachability at $LAGO_API_URL"
lago_ping=$(curl -sS -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $LAGO_API_KEY" \
  "$LAGO_API_URL/api/v1/organizations/current" || true)
[[ "$lago_ping" == "200" ]] || fail "Lago /api/v1/organizations/current returned $lago_ping" 2

log "checking Stripe reachability"
stripe_ping=$(curl -sS -o /dev/null -w "%{http_code}" \
  -u "$STRIPE_SECRET_KEY:" \
  "https://api.stripe.com/v1/balance" || true)
[[ "$stripe_ping" == "200" ]] || fail "Stripe /v1/balance returned $stripe_ping" 3

# --- plan (create if missing) -------------------------------------------------

plan_status=$(curl -sS -o /tmp/lago-plan.json -w "%{http_code}" \
  -H "Authorization: Bearer $LAGO_API_KEY" \
  "$LAGO_API_URL/api/v1/plans/$PLAN_CODE" || true)

if [[ "$plan_status" == "404" ]]; then
  log "creating plan $PLAN_CODE (10 USD/month, no metered charges)"
  create_status=$(curl -sS -o /tmp/lago-plan.json -w "%{http_code}" \
    -X POST "$LAGO_API_URL/api/v1/plans" \
    -H "Authorization: Bearer $LAGO_API_KEY" \
    -H "Content-Type: application/json" \
    -d "$(jq -n --arg code "$PLAN_CODE" '{
      plan: { name: "Smoke Test Plan", code: $code, interval: "monthly",
              amount_cents: 1000, amount_currency: "USD", pay_in_advance: true }
    }')")
  [[ "$create_status" == "200" || "$create_status" == "201" ]] \
    || { cat /tmp/lago-plan.json; fail "plan create returned $create_status" 4; }
elif [[ "$plan_status" != "200" ]]; then
  cat /tmp/lago-plan.json
  fail "plan lookup returned $plan_status" 4
fi

# --- customer -----------------------------------------------------------------

log "creating Lago customer $CUSTOMER_CODE"
cust_status=$(curl -sS -o /tmp/lago-cust.json -w "%{http_code}" \
  -X POST "$LAGO_API_URL/api/v1/customers" \
  -H "Authorization: Bearer $LAGO_API_KEY" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg code "$CUSTOMER_CODE" '{
    customer: {
      external_id: $code,
      name: "Smoke Test",
      email: "smoke+\($code)@jedi-knights.dev",
      billing_configuration: { payment_provider: "stripe" }
    }
  }')")
[[ "$cust_status" == "200" || "$cust_status" == "201" ]] \
  || { cat /tmp/lago-cust.json; fail "customer create returned $cust_status" 5; }

# --- subscription -------------------------------------------------------------

log "subscribing customer to $PLAN_CODE"
sub_status=$(curl -sS -o /tmp/lago-sub.json -w "%{http_code}" \
  -X POST "$LAGO_API_URL/api/v1/subscriptions" \
  -H "Authorization: Bearer $LAGO_API_KEY" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg cust "$CUSTOMER_CODE" --arg plan "$PLAN_CODE" '{
    subscription: {
      external_customer_id: $cust, plan_code: $plan,
      external_id: "smoke_sub_\($cust)"
    }
  }')")
[[ "$sub_status" == "200" || "$sub_status" == "201" ]] \
  || { cat /tmp/lago-sub.json; fail "subscription create returned $sub_status" 6; }

# --- verify in Stripe ---------------------------------------------------------

log "verifying customer landed in Stripe"
sleep 3  # Lago -> Stripe customer create is async
stripe_cust=$(curl -sS \
  -u "$STRIPE_SECRET_KEY:" \
  "https://api.stripe.com/v1/customers/search" \
  --data-urlencode "query=metadata[\"lago_customer_id\"]:\"$CUSTOMER_CODE\"" \
  | jq -r '.data[0].id // empty')
[[ -n "$stripe_cust" ]] || fail "no Stripe customer with lago_customer_id=$CUSTOMER_CODE" 7
log "Stripe customer: $stripe_cust"

# --- verify webhook came back -------------------------------------------------

log "waiting up to ${WEBHOOK_TIMEOUT}s for Stripe->Lago webhook to fire"
deadline=$(( $(date +%s) + WEBHOOK_TIMEOUT ))
webhook_seen=0
while [[ $(date +%s) -lt $deadline ]]; do
  events=$(curl -sS \
    -H "Authorization: Bearer $LAGO_API_KEY" \
    "$LAGO_API_URL/api/v1/events?external_customer_id=$CUSTOMER_CODE" \
    | jq -r '.events[]?.transaction_id // empty' | head -1)
  if [[ -n "$events" ]]; then
    webhook_seen=1
    break
  fi
  sleep 2
done
[[ $webhook_seen -eq 1 ]] || fail "no Lago event for $CUSTOMER_CODE within ${WEBHOOK_TIMEOUT}s" 8

log "PASS: Lago↔Stripe wired end-to-end"
echo
echo "Summary:"
echo "  Lago customer:  $CUSTOMER_CODE"
echo "  Stripe customer: $stripe_cust"
echo "  Plan:           $PLAN_CODE"
echo
echo "Cleanup (optional):"
echo "  curl -X DELETE -H \"Authorization: Bearer \$LAGO_API_KEY\" \\"
echo "    \"\$LAGO_API_URL/api/v1/customers/$CUSTOMER_CODE\""
