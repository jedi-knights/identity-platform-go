# Touchline plan catalog

Source-of-truth definitions for the initial Touchline paid plans in Lago.
The three JSON files in this directory are the canonical plan bodies; apply
them to a running Lago via [`apply.sh`](./apply.sh).

**Related issue:** [#152 E2-S2](https://github.com/jedi-knights/identity-platform-go/issues/152). Part of [Epic 2 (#139)](https://github.com/jedi-knights/identity-platform-go/issues/139).

## The catalog

| Plan file                                        | Code              | Price      | Trial   | Match quota | Seat allowance | Entitlements tier |
|--------------------------------------------------|-------------------|------------|---------|-------------|----------------|-------------------|
| [`touchline-free.json`](./touchline-free.json)   | `touchline-free`  | $0 / mo    | —       | 3 / month   | 1              | `free`            |
| [`touchline-coach.json`](./touchline-coach.json) | `touchline-coach` | $12 / mo   | 7 days  | unlimited   | 1              | `coach`           |
| [`touchline-club.json`](./touchline-club.json)   | `touchline-club`  | $49 / mo   | 7 days  | unlimited   | 10             | `club`            |

Plan codes are **stable identifiers**. The forthcoming `entitlements-service`
will branch on `plan.metadata.entitlements_tier` (or fall back to `plan.code`)
to decide feature access. Do not rename the codes without a coordinated
migration.

## Enforcement split — architectural decision

**Lago prices; `entitlements-service` enforces.** This is a durable decision
recorded in [ADR-0027](../../../docs/adr/0027-entitlements-enforces-quota-lago-prices.md), not an interim state. Do
not migrate quota enforcement into Lago meters when Epic 3 lands.

- **Recurring price + trial length** — Lago (`amount_cents`, `trial_period`)
- **Match-quota hard cap** on Free — `entitlements-service` reads
  `plan.metadata.match_quota` at auth-check time and denies the 4th match
- **Seat allowance** on Club — `entitlements-service` reads
  `plan.metadata.seat_allowance` when adding a member; Lago has no seat
  concept regardless
- **Usage reporting** on the `matches` metric (Epic 3) — Lago tracks
  usage for dashboards and future overage pricing, **but does not gate
  access**. The billable metric enables reporting, not enforcement.

**Why one enforcement point:** entitlements-service exists regardless (for
role gates, tier features, feature flags). Duplicating quota enforcement
in Lago's graduated `charges` would mean two accounting paths for one
decision, and Lago's meter is designed for overage billing, not hard
blocks. Keeping the block in the auth layer makes "why was this request
denied?" traceable to one code path.

Per-seat overage pricing on Club is out of E2-S2 scope (contact-sales
flow).

## Applying the catalog

Open a `fly proxy` tunnel to Lago's API (from `../README.md`), then:

```bash
set -a; source infra/stripe/secrets.env; set +a   # provides LAGO_API_KEY + LAGO_API_URL
./infra/lago/plans/apply.sh
```

The script is idempotent — it prints `unchanged` / `updating` / `creating`
per plan and exits 0 on success. `--dry-run` shows what would change without
mutating.

## Verifying in the admin UI

Open the Lago UI (`fly proxy 8080:80 -a jk-lago-front`) and navigate to
*Plans*. You should see the three plans listed with the prices and trial
periods above. Clicking each plan reveals the `metadata` block with the
entitlements keys.

## Modifying a plan

Edit the JSON, commit, re-run `apply.sh`. **Do not** modify a plan directly
in the Lago admin UI — the JSON files are the source of truth, and a UI-only
edit will drift back to the JSON on the next apply.

**Safe fields to change** on an active plan (existing subscriptions keep
their pricing until the next billing period):

- `name`, `description`
- `metadata` (entitlements-service picks up the new values on next lookup)
- `trial_period` (affects only new subscriptions)

**Fields that require a plan-migration playbook** (existing subscribers
get grandfathered under the old price; new subscribers get the new one):

- `amount_cents`, `amount_currency`, `interval`

Plan migration is not in E2-S2 scope; when the first pricing change comes,
write the playbook then.

## Removing a plan

`apply.sh` never deletes — removed JSON files are simply ignored. To remove
a plan from Lago, do it explicitly:

```bash
curl -X DELETE \
  -H "Authorization: Bearer $LAGO_API_KEY" \
  "$LAGO_API_URL/api/v1/plans/touchline-coach"
```

Lago refuses to delete a plan with active subscriptions — migrate those
first.
