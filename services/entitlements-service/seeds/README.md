# Touchline entitlements catalog seed

Populates `resources`, `bundles`, `bundle_resources`, `plans`, and
`plan_bundles` with the initial reference data for the Touchline product.

**Related issue:** [#156 E3-S3](https://github.com/jedi-knights/identity-platform-go/issues/156). Part of [Epic 3 (#140)](https://github.com/jedi-knights/identity-platform-go/issues/140).

## Applying

Apply the schema migration first (E3-S2 landed it), then the seed:

```bash
export ENTITLEMENTS_DATABASE_URL="postgres://user:pass@host:5432/entitlements"
./services/entitlements-service/seeds/apply.sh
```

`apply.sh` is idempotent — safe to re-run. Every INSERT uses `ON CONFLICT
DO UPDATE` (for rows keyed by `code`) or `ON CONFLICT DO NOTHING` (for
join rows), so re-runs upsert rather than duplicate.

The script asserts minimum row counts after apply and exits non-zero if
the seed appears incomplete.

## Catalog contents

### Resources (25)

| Category        | Codes                                                                                                                                        |
|-----------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| `app`           | `app:touchline`, `app:scout-sleuth` (placeholder)                                                                                            |
| `mcp-server`    | `mcp:jk-mcp-ecnl`, `mcp:jk-mcp-ncaa-soccer`, `mcp:jk-mcp-nfl`, `mcp:jk-mcp-nwsl`                                                             |
| `mcp-tool`      | 6 ECNL tools, 5 NWSL tools, 1 NCAA placeholder, 1 NFL placeholder                                                                            |
| `data-source`   | `data:sports-reference`, `data:espn-scoreboards` (placeholders — real feed list to be confirmed)                                             |
| `feature`       | `feature:touchline:match_review`, `hd_replays`, `multi_seat`, `pdf_export`                                                                   |

### Bundles (6)

| Bundle code                | Purpose                                                            |
|----------------------------|--------------------------------------------------------------------|
| `bundle-free`              | Baseline capabilities on the free tier                             |
| `bundle-touchline-coach`   | Full Coach tier                                                    |
| `bundle-touchline-club`    | Club tier extras (multi-seat + all sport MCPs)                     |
| `bundle-ncaa-d1-women`     | Add-on: NCAA Soccer MCP scoped to D1 women                         |
| `bundle-nwsl-full`         | Add-on: unrestricted NWSL MCP access                               |
| `bundle-youth-free-tier`   | ECNL youth-only free tier                                          |

### Plan → bundle mappings (7)

Higher tiers **inherit** lower tiers' bundles — the "what does Coach get?"
answer is a UNION over all bundles the plan maps to.

| Plan code          | Bundles granted                                                              |
|--------------------|------------------------------------------------------------------------------|
| `touchline-free`   | `bundle-free`, `bundle-youth-free-tier`                                      |
| `touchline-coach`  | `bundle-free`, `bundle-touchline-coach`                                      |
| `touchline-club`   | `bundle-free`, `bundle-touchline-coach`, `bundle-touchline-club`             |

`bundle-ncaa-d1-women` and `bundle-nwsl-full` are **add-on bundles** —
not attached to any plan by default. Sold separately in a future flow
(Epic 4+).

Plan codes match `infra/lago/plans/*.json` — the join key from Lago's
subscription record to the entitlements catalog.

### Bundle → resource mappings

**`bundle-free`** — Touchline app + `match_review` feature (with
`monthly_quota: 3` constraint per ADR-0027) + ECNL server + 5 public ECNL
tools.

**`bundle-touchline-coach`** — Touchline app + `match_review` unlimited
(`monthly_quota: null`) + `hd_replays` + `pdf_export` + ECNL RPI + NWSL
public tools.

**`bundle-touchline-club`** — `multi_seat` feature (with
`seat_allowance: 10`) + all four MCP servers + full NWSL / NCAA / NFL
tool access.

**`bundle-ncaa-d1-women`** — NCAA Soccer MCP with `division: "d1"` and
`gender: "women"` constraints on both server and tool rows. Constraints
are picked up by the resolver at auth-check time.

**`bundle-nwsl-full`** — NWSL server + all 5 tools, no constraints.

**`bundle-youth-free-tier`** — ECNL server + 4 public tools (no RPI, no
downloads).

## Constraints — how per-membership metadata flows

`bundle_resources.constraints` (JSONB) carries scoping / quota data that
is bundle-and-resource-specific:

- **Quotas** — `{"monthly_quota": 3}` on `bundle-free`'s
  `feature:touchline:match_review`. Enforced by entitlements-service at
  check time per ADR-0027.
- **Scoping** — `{"division": "d1", "gender": "women"}` on
  `bundle-ncaa-d1-women` narrows an otherwise-full MCP to a subset.
  Enforced by the MCP server reading these keys from the auth context.
- **Seats** — `{"seat_allowance": 10}` on `bundle-touchline-club`'s
  `multi_seat` feature is the enforcement contract for `account_seats`
  count limits.

The shape is intentionally JSONB (not typed columns) — different
resource types accept different keys, and the resolver reads whatever
the resource expects.

### Overlap and merge — a note for the resolver

Bundles are **self-contained** — `bundle-touchline-coach` grants
`match_review` with `{"monthly_quota": null}` (unlimited) even though
`bundle-free` also grants it with `{"monthly_quota": 3}`. That's
intentional: a bundle must be independently meaningful for add-on sales
to work, so Coach cannot depend on Free being present to grant unlimited
reviews.

When a plan maps to multiple bundles that all grant the same resource,
the resolver (Epic 3 follow-up) must **merge constraints by picking the
most permissive value per key**:

- `monthly_quota: null` (unlimited) beats any finite value
- `seat_allowance: N` — take MAX
- Boolean feature flags — OR
- Scope filters (e.g. `division`, `gender`) — set-union

The merge rule is monotonic in the "more entitlements = more permissive"
direction. Verify with a query like the one in the seed test:

```sql
SELECT DISTINCT r.code, br.constraints
FROM plans p
JOIN plan_bundles pb    ON pb.plan_id = p.id
JOIN bundles b          ON b.id = pb.bundle_id
JOIN bundle_resources br ON br.bundle_id = b.id
JOIN resources r        ON r.id = br.resource_id
WHERE p.code = 'touchline-coach'
ORDER BY r.code;
```

Coach's `match_review` returns two rows — the merge rule picks
`{monthly_quota: null}`.

## Placeholders in this seed

Marked with "Placeholder — ..." in the SQL. Follow-up when the actual
data is available:

- `app:scout-sleuth` — product not yet in market
- `data:sports-reference`, `data:espn-scoreboards` — real feed list TBD
- `tool:jk-mcp-ncaa-soccer:get_rpi` — one placeholder tool; full NCAA
  tool inventory not enumerated
- `tool:jk-mcp-nfl:get_scoreboard` — one placeholder tool; full NFL
  tool inventory not enumerated

Adding real tools later: append the `INSERT INTO resources ...` rows and
map them into the appropriate `bundle_resources` batch. Re-run
`apply.sh` — upsert semantics make this safe.

## Testing

`apply.sh` runs against a live Postgres and asserts minimum row counts:

- resources ≥ 25
- bundles ≥ 6
- bundle_resources ≥ 37
- plans ≥ 3
- plan_bundles ≥ 7

Exit codes: 0 = ok, 2 = Postgres unreachable, 3 = seed SQL errored,
4 = post-seed row count assertions failed.
