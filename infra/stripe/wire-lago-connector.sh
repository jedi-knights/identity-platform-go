#!/usr/bin/env bash
# Wire Stripe test-mode into a running Lago instance (E2-S1 / issue #151).
#
# Idempotent: creates the Stripe payment provider if absent, updates it if
# present. Safe to re-run.
#
# Requires env vars (source infra/stripe/secrets.env first):
#   STRIPE_SECRET_KEY               — sk_test_... from Stripe Dashboard
#   STRIPE_WEBHOOK_SIGNING_SECRET   — whsec_... (see README §4; set after webhook creation)
#   LAGO_API_KEY                    — from Lago admin UI → Developers
#   LAGO_API_URL                    — e.g. http://localhost:3000 via `fly proxy`
#
# Usage (from repo root):
#   set -a; source infra/stripe/secrets.env; set +a
#   ./infra/stripe/wire-lago-connector.sh [--code stripe_test]
#
# What it does:
#   1. POSTs to Lago /api/v1/payment_providers/stripe with the Stripe secret
#      key + webhook signing secret. Lago verifies the key with Stripe's API.
#   2. Prints Lago's inbound webhook URL — paste this into Stripe Dashboard →
#      Developers → Webhooks → Add endpoint. Then update
#      STRIPE_WEBHOOK_SIGNING_SECRET in secrets.env and re-run this script.
#
# What it deliberately does NOT do:
#   - Create the Stripe webhook endpoint (Stripe API allows it, but the
#     signing-secret round-trip is easier via the Dashboard for a one-time
#     setup — see README §4).
#   - Configure success/cancel redirect URLs (product-specific; set once
#     the tenant frontend exists).

set -euo pipefail

CODE="stripe_test"
DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --code)    CODE="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

: "${STRIPE_SECRET_KEY:?set STRIPE_SECRET_KEY (source infra/stripe/secrets.env)}"
: "${LAGO_API_KEY:?set LAGO_API_KEY}"
: "${LAGO_API_URL:?set LAGO_API_URL}"

# The signing secret is optional on first pass — connector must exist before
# Stripe will accept a webhook endpoint. Second pass fills it in.
STRIPE_WEBHOOK_SIGNING_SECRET="${STRIPE_WEBHOOK_SIGNING_SECRET:-}"

if [[ "$STRIPE_SECRET_KEY" != sk_test_* ]]; then
  echo "refusing: STRIPE_SECRET_KEY is not a test-mode key (must start with sk_test_)" >&2
  echo "if this is intentional, use infra/stripe/wire-lago-connector.sh with --live (not yet implemented)" >&2
  exit 3
fi

payload=$(jq -n \
  --arg code "$CODE" \
  --arg name "Stripe (test mode)" \
  --arg secret_key "$STRIPE_SECRET_KEY" \
  --arg webhook_secret "$STRIPE_WEBHOOK_SIGNING_SECRET" \
  '{payment_provider: {
      code: $code,
      name: $name,
      secret_key: $secret_key,
      success_redirect_url: null
   }
   | if $webhook_secret != "" then . + {webhook_secret: $webhook_secret} else . end
  }')

log() { printf '[wire-lago] %s\n' "$*"; }
run() { if [[ $DRY_RUN -eq 1 ]]; then echo "  DRY: $*"; else eval "$*"; fi; }

log "checking if payment provider '$CODE' already exists on Lago"
existing_status=$(curl -sS -o /tmp/lago-check.json -w "%{http_code}" \
  -H "Authorization: Bearer $LAGO_API_KEY" \
  "$LAGO_API_URL/api/v1/payment_providers/$CODE" || true)

if [[ "$existing_status" == "200" ]]; then
  log "connector exists — updating (PUT)"
  method=PUT
  url="$LAGO_API_URL/api/v1/payment_providers/$CODE"
elif [[ "$existing_status" == "404" ]]; then
  log "connector missing — creating (POST)"
  method=POST
  url="$LAGO_API_URL/api/v1/payment_providers/stripe"
else
  log "unexpected status $existing_status from Lago:"
  cat /tmp/lago-check.json
  exit 4
fi

if [[ $DRY_RUN -eq 1 ]]; then
  echo "  DRY: $method $url"
  echo "  DRY: payload = $(echo "$payload" | jq -c '.payment_provider | .secret_key = "sk_test_***" | .webhook_secret = (.webhook_secret // "<unset>" | if . == "" then "<unset>" else "whsec_***" end)')"
else
  http_status=$(curl -sS -o /tmp/lago-resp.json -w "%{http_code}" \
    -X "$method" "$url" \
    -H "Authorization: Bearer $LAGO_API_KEY" \
    -H "Content-Type: application/json" \
    -d "$payload")
  if [[ "$http_status" != "200" && "$http_status" != "201" ]]; then
    log "Lago returned $http_status:"
    cat /tmp/lago-resp.json
    exit 5
  fi
  log "connector configured (HTTP $http_status)"
fi

# Print the webhook URL to paste into Stripe Dashboard.
# Lago's webhook path is /webhooks/stripe/<organization_id>. The org ID is
# in the response (or fetch it separately).
org_id=$(curl -sS \
  -H "Authorization: Bearer $LAGO_API_KEY" \
  "$LAGO_API_URL/api/v1/organizations/current" \
  | jq -r '.organization.id // .id // empty')

if [[ -n "$org_id" ]]; then
  echo
  echo "Next: add the following webhook endpoint in Stripe Dashboard →"
  echo "  Developers → Webhooks → Add endpoint:"
  echo
  echo "  Endpoint URL:  $LAGO_API_URL/webhooks/stripe/$org_id"
  echo "  Events:        payment_intent.succeeded, payment_intent.payment_failed,"
  echo "                 setup_intent.succeeded, charge.succeeded, charge.refunded,"
  echo "                 customer.updated"
  echo
  echo "Then copy the endpoint's signing secret into secrets.env as"
  echo "STRIPE_WEBHOOK_SIGNING_SECRET and re-run this script."
else
  echo "warning: could not resolve Lago organization ID — is LAGO_API_KEY correct?"
fi

if [[ -z "$STRIPE_WEBHOOK_SIGNING_SECRET" ]]; then
  echo
  echo "NOTE: STRIPE_WEBHOOK_SIGNING_SECRET was empty — connector is wired for"
  echo "outbound calls to Stripe, but incoming webhook signatures cannot yet be"
  echo "verified. Re-run this script after adding the secret to secrets.env."
fi
