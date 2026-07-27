# Stripe → Lago connector (test mode)

Wires a Stripe test-mode account into the self-hosted Lago instance
so paid signups can complete a test-card checkout end-to-end.

- [`wire-lago-connector.sh`](./wire-lago-connector.sh) — POSTs to Lago to configure the Stripe payment provider
- [`smoke-test.sh`](./smoke-test.sh) — end-to-end verification (customer → subscription → webhook)
- [`secrets.env.example`](./secrets.env.example) — template for the four required env vars

**Related issue:** [#151 E2-S1](https://github.com/jedi-knights/identity-platform-go/issues/151). Part of [Epic 2 (#139)](https://github.com/jedi-knights/identity-platform-go/issues/139).

## Prerequisites

- Lago is deployed and reachable — see [`../lago/README.md`](../lago/README.md)
- You've completed post-deploy admin-UI steps 1–5 (admin user + API key)
- `curl`, `jq`, `bash` >= 4

## Setup sequence

### 1. Create a Stripe test-mode account

Go to https://dashboard.stripe.com/register. Fill in the minimum required
business info. **Do not activate the account for live payments** — this
runbook is for test mode only. Test mode is on by default for new accounts.

### 2. Capture the test-mode API keys

Dashboard → Developers → API keys (with the "Viewing test data" toggle **on**):

- **Publishable key** — starts `pk_test_...`
- **Secret key** — click "Reveal test key" → starts `sk_test_...`

Save both into your local secrets file:

```bash
cp infra/stripe/secrets.env.example infra/stripe/secrets.env
$EDITOR infra/stripe/secrets.env  # fill in STRIPE_SECRET_KEY and STRIPE_PUBLISHABLE_KEY
```

Also mirror the secret key into Fly's secret manager so Lago has it out of band:

```bash
fly secrets set -a jk-lago-api \
  STRIPE_TEST_SECRET_KEY_MIRROR="$STRIPE_SECRET_KEY"
```

Lago itself stores the key internally (via the connector API in step 3);
this mirror is for disaster recovery, not runtime.

### 3. Configure the Stripe connector in Lago

Open a `fly proxy` tunnel to the Lago API (from `../lago/README.md`):

```bash
fly proxy 3000:3000 -a jk-lago-api &
export LAGO_API_URL=http://localhost:3000
```

Then run the wiring script (first pass — no webhook secret yet):

```bash
set -a; source infra/stripe/secrets.env; set +a
./infra/stripe/wire-lago-connector.sh
```

The script prints the Lago webhook URL you'll paste into Stripe in the next step.

### 4. Register the Stripe → Lago webhook

Dashboard → Developers → Webhooks → **Add endpoint**:

- **Endpoint URL:** copy the URL the wire script printed (looks like
  `https://jk-lago-api.internal:3000/webhooks/stripe/<org_id>`)
- **Events to send:**
  - `payment_intent.succeeded`
  - `payment_intent.payment_failed`
  - `setup_intent.succeeded`
  - `charge.succeeded`
  - `charge.refunded`
  - `customer.updated`
- Click **Add endpoint**
- On the endpoint's page, click **Reveal signing secret** → starts `whsec_...`
- Copy it into `infra/stripe/secrets.env` as `STRIPE_WEBHOOK_SIGNING_SECRET`

Re-run the wiring script to persist the signing secret into Lago:

```bash
set -a; source infra/stripe/secrets.env; set +a
./infra/stripe/wire-lago-connector.sh
```

### 5. Verify in the Lago admin UI

`fly proxy` the front app (still from `../lago/README.md`):

```bash
fly proxy 8080:80 -a jk-lago-front &
open http://localhost:8080
```

Navigate to *Settings → Integrations → Stripe*. Expected state:

- Status: **Connected**
- Code: `stripe_test`
- Webhook signing secret: `whsec_***` (masked)

### 6. Smoke-test end-to-end

```bash
set -a; source infra/stripe/secrets.env; set +a
./infra/stripe/smoke-test.sh
```

Success looks like:

```
[smoke] checking Lago reachability at http://localhost:3000
[smoke] checking Stripe reachability
[smoke] creating Lago customer smoke_test_1730000000
[smoke] subscribing customer to smoke_test_plan
[smoke] verifying customer landed in Stripe
[smoke] Stripe customer: cus_QzABC...
[smoke] waiting up to 30s for Stripe->Lago webhook to fire
[smoke] PASS: Lago↔Stripe wired end-to-end
```

If any step fails, the script exits non-zero with a specific code (see
`smoke-test.sh` header — 2=Lago unreachable, 3=Stripe unreachable, 7=customer
did not land in Stripe, 8=webhook did not fire, etc.). See [§Troubleshooting](#troubleshooting).

## Acceptance criteria (from #151)

Map from AC → verification step:

| AC | Verified by |
|----|-------------|
| Stripe account created; test-mode API keys captured in secret manager | §1, §2 (keys land in Fly secrets + local secrets.env) |
| Lago admin UI shows Stripe as connected payment provider | §5 (visual check) |
| Test-card Checkout Session completes and creates a Stripe customer + subscription | §6 (smoke-test.sh exit 0; verifies customer via Stripe search API) |
| Stripe→Lago webhook verified in Lago event log | §6 (webhook_seen check via Lago /api/v1/events) |

## Troubleshooting

| Symptom                                          | Likely cause                                     | Fix                                                                                    |
|--------------------------------------------------|--------------------------------------------------|----------------------------------------------------------------------------------------|
| wire-lago-connector.sh: HTTP 401 from Lago       | Wrong `LAGO_API_KEY`                             | Regenerate at Lago admin → Developers → API keys                                       |
| wire-lago-connector.sh: HTTP 422 "invalid secret"| Stripe rejected the key                          | Confirm key is `sk_test_`; not revoked in Dashboard                                    |
| Stripe webhook shows "Signature verification failed" | `STRIPE_WEBHOOK_SIGNING_SECRET` mismatch     | Re-copy from Stripe Dashboard → Webhooks → endpoint → Signing secret; re-run wire      |
| smoke-test.sh exits 7 (no Stripe customer)       | Stripe key not persisted to Lago                 | Re-run wire-lago-connector.sh; check `_test_secret_key` mirror in Fly secrets          |
| smoke-test.sh exits 8 (no webhook)               | Stripe endpoint URL not reachable from Stripe    | Stripe cannot reach `jk-lago-api.internal` — endpoint must be a public gateway URL     |

## Notes

- **Endpoint URL reachability:** Stripe's servers push webhooks *inbound* to
  the Lago API. The `.internal` hostname is only reachable from Fly's 6PN
  network, so before end-to-end works you must expose Lago's `/webhooks/*`
  path via the `api-gateway` at a public URL. Track this dependency in
  Epic 4 (api-gateway); until then, smoke-test.sh will exit 8.
- **Live mode is out of scope for E2-S1.** Live-mode wiring will be its own
  runbook (`infra/stripe/live-mode.md`) once the test-mode flow is solid.
- **Rotating the Stripe secret key:** revoke the old key in Stripe Dashboard
  first, then re-run `wire-lago-connector.sh` with the new key. There is no
  overlap window — plan a maintenance minute.
