# Lago billable metrics

Source-of-truth definitions for Lago billable metrics used by the Touchline
plan catalog and downstream services (metering, entitlements).

**Related issue:** [#153 E2-S3](https://github.com/jedi-knights/identity-platform-go/issues/153). Part of [Epic 2 (#139)](https://github.com/jedi-knights/identity-platform-go/issues/139).

## The catalog

| Metric file                                        | Code             | Aggregation | Filter dimension | Used by plan(s)             |
|----------------------------------------------------|------------------|-------------|------------------|------------------------------|
| [`mcp-tool-calls.json`](./mcp-tool-calls.json)     | `mcp_tool_calls` | `count_agg` | `tool_id`        | `touchline-coach`, `touchline-club` |

## How per-tool pricing works

`mcp_tool_calls` counts one event per MCP tool invocation. Each event carries
a `tool_id` property identifying which server + method was called
(e.g. `jk-mcp-nwsl:get_standings`).

**Filter dimension.** The metric declares `tool_id` as a filter with an
allowlist of tool identifiers. Only tools in that list can carry a distinct
price; events for unlisted tools still increment the count but do not
trigger a filter-specific rate.

**Per-tool rates on plans.** The plan's `charges[]` entry references
`mcp_tool_calls` and lists filter-specific `properties.amount` values:

```jsonc
{
  "charges": [
    {
      "billable_metric_code": "mcp_tool_calls",
      "charge_model": "standard",
      "properties": { "amount": "0" },       // default rate for unfiltered tools
      "filters": [
        {
          "invoice_display_name": "NWSL get_standings",
          "properties": { "amount": "0.002" },
          "values": { "tool_id": ["jk-mcp-nwsl:get_standings"] }
        },
        {
          "invoice_display_name": "NCAA get_rpi",
          "properties": { "amount": "0.01" },
          "values": { "tool_id": ["jk-mcp-ncaa:get_rpi"] }
        }
      ]
    }
  ]
}
```

**Default rate is $0.** Tools not listed in a filter bill at
`properties.amount = "0"`. New tools default to free until priced —
safer than defaulting to a surprise rate. When adding a new priced
tool: add its ID to `mcp-tool-calls.json`'s `filters.values`, add a
matching filter entry to the plan JSONs, re-run both `apply.sh`
scripts.

## Ordering — metrics before plans

Lago validates that a plan's `charges[].billable_metric_code` references
an existing metric on plan create. **Apply metrics before plans**:

```bash
set -a; source infra/stripe/secrets.env; set +a
./infra/lago/metrics/apply.sh
./infra/lago/plans/apply.sh
```

The lago README's post-deploy sequence handles this ordering automatically
(step 9 metrics → step 10 plans).

## Applying

```bash
set -a; source infra/stripe/secrets.env; set +a
./infra/lago/metrics/apply.sh          # idempotent; --dry-run supported
```

## Smoke test

Full end-to-end verification — creates a customer, fires priced events,
reads back the invoice preview, asserts amounts:

```bash
set -a; source infra/stripe/secrets.env; set +a
./infra/lago/metrics/smoke-test.sh
```

Success looks like:

```
[metric-smoke] sending 100 events for tool_id=jk-mcp-nwsl:get_standings
[metric-smoke] sending 50 events for tool_id=jk-mcp-ncaa:get_rpi
[metric-smoke] fetching invoice preview for metric_smoke_1730000000
[metric-smoke] invoice preview: NWSL=20 cents, NCAA=50 cents
[metric-smoke] expected:        NWSL=20 cents, NCAA=50 cents
[metric-smoke] PASS: per-tool pricing applied correctly
```

If the invoice preview shows wrong amounts, the smoke test exits with a
distinct code — 3 (metric/plan missing), 6 (line item missing), 7 (amount
mismatch). See the script header.

## Modifying a metric

`aggregation_type` and `field_name` are **immutable in Lago once the
metric has events**. Changing them requires:

1. Create a new metric with a new code (e.g. `mcp_tool_calls_v2`)
2. Update plan `charges` to reference the new code
3. Migrate reporting / entitlements consumers to the new code
4. Deprecate the old metric only when no plan references it

Safe fields to change on a live metric:

- `name`, `description`, `invoice_display_name`
- `filters.values` — adding a new `tool_id` to price is safe (existing
  events unchanged)

## Relationship to ADR-0027

Per [ADR-0027](../../../docs/adr/0027-entitlements-enforces-quota-lago-prices.md),
`mcp_tool_calls` is used for **pricing** (paid plans) and **usage reporting**.
It is NOT used to enforce the Free plan's `match_quota` — that stays in
`entitlements-service` reading `plan.metadata.match_quota`. Do not add
`mcp_tool_calls` (or a `matches` metric) to the Free plan as a graduated
charges block for hard-cap enforcement.
