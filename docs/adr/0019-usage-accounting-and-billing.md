# ADR-0019: Usage Accounting via the Audit Pipeline + Lago

**Status**: Proposed
**Date**: 2026-06-27

## Context

ADR-0018 establishes a single agent-audit event envelope and explicitly
permits emission to *drop on overflow* so the audit path can never fail the
underlying operation. That is the right posture for audit. It is the wrong
posture for accounting.

As soon as the portfolio bills anyone, enforces per-cost quotas, or allocates
paid LLM cost back to a user, agent, or tenant, the platform needs:

- **Per-actor usage counts** with the granularity already present in the
  ADR-0018 envelope (`actor_type`, `actor_id`, `subject_id`, `resource`,
  `action`, `attrs.duration_ms`, `attrs.tokens_in/out`,
  `attrs.upstream_cost_usd`, `act` chain depth for delegated calls).
- **At-least-once capture**. A dropped event is a missing line item.
- **A customer / plan / invoice model**. Aggregating events is the easy
  half; mapping aggregates onto commercial terms (subscriptions, wallets,
  proration, refunds) is the hard half.

Building that ourselves is unnecessary. [Lago](https://www.getlago.com/) is
open source, self-hostable, event-ingestion-first, and built for usage-based
billing rather than seats. The integration shape is mechanical: the existing
audit envelope already carries the data; only the sink and the field
renaming differ.

The portfolio-wide context (gap analysis, triggers, mermaid data-flow
sketch) lives in `architecture/docs/agentic-posture.md` under "Usage
accounting".

## Decision

Treat the ADR-0018 audit stream as the canonical event stream for usage
accounting. Add a durable, at-least-once sink to `go-platform/audit`. Run a
separate metering worker that transforms audit events into Lago events. Keep
real-time quota and cost enforcement inside the portfolio; let Lago own
plans, customers, and invoices.

### Pipeline

```
auth-server                                       Lago
identity-service                                  plans
client-registry      ┌──────────┐   ┌──────────┐  subscriptions
introspection ─────► │ audit    │─► │ metering │─►customers
policy-service       │ pipeline │   │ shim     │  billable metrics
jk-mcp-nwsl          └──┬───────┘   └──────────┘  invoices / wallets
jk-mcp-ecnl             │
                        ▼ at-least-once sink (durable)
                     Postgres or NATS JetStream
```

### Sink durability

`go-platform/audit` (proposed in ADR-0018) gains a registered sink:

- **`durable`** — append-only writes to a Postgres table
  (`audit_events`) inside the request path, or publish to a NATS JetStream
  subject with `Persistent` storage and synchronous ack. The sink returns
  success only after the write is durable.
- The existing **`stderr_json`** and **`otel_log`** sinks remain best-effort.

Services emit through the same `Emit(ctx, Event{...})` call; sink selection
happens at composition time via `go-platform/container`. A service can wire
multiple sinks — typical production wiring is `stderr_json` *and* `durable`
so operations and accounting feeds run side by side.

The durable sink is on the request path, but on a separate channel from the
best-effort sink. If the durable sink fails:

| Operation context | Behavior |
|---|---|
| Token issuance / introspection / exchange | Fail the request — accounting cannot have gaps for paid operations |
| MCP tool call | Fail the request when `attrs.cost_class != "free"`; succeed when `cost_class == "free"` |
| Policy decision emission | Best-effort — already covered by audit, not billed |

Service operators choose per-event-type whether the durable sink is
"required" (fail the request on durable-sink error) or "best-effort"
(swallow the error, increment a metric). The classification lives in
configuration, not code, so accounting policy is operationally tunable.

### Metering worker

A new out-of-process worker subscribes to the durable sink and transforms
each event into one or more Lago events. The transformation is purely
structural — Lago expects a flat JSON shape and field names matching the
billable metric's configured filter set.

```
audit_event                            lago_event
─────────────────────                  ────────────────────
event_type: tool_invoked       ───►    transaction_id: <event_id>
actor_type: agent                      external_subscription_id:
actor_id: agent-claude-abc                <subject_id or actor_id, per plan>
subject_id: user-omar                  code: tool_invocation
resource: tool:get_standings           timestamp: <event.timestamp>
attrs.duration_ms: 142                 properties:
attrs.upstream_cost_usd: 0.0           ▸ tool: get_standings
                                       ▸ duration_ms: 142
                                       ▸ upstream_cost_usd: 0.0
                                       ▸ act_chain_depth: 2
```

The worker is idempotent — Lago dedupes by `transaction_id`, which we map
1:1 to the audit `event_id`. Replays and reconciliation runs are safe.

The worker ships in its own repo (`jk-metering`) rather than this one —
keeping the auth-server's responsibility tight (issue tokens, emit events)
and isolating Lago credentials.

### Billing identity (who pays)

Token exchange (ADR-0016) and RAR (ADR-0017) introduce delegation chains
where the `actor` (immediate caller) and `subject` (resource owner) differ.
For accounting, "who is the Lago customer" is a policy choice with three
options, selectable per plan:

| Plan billing-identity field | Lago `external_subscription_id` | Use case |
|---|---|---|
| `subject` (default) | `subject_id` | Bill the user even when an agent acted for them — the "user owns the cost" model |
| `actor` | `actor_id` | Bill the agent's operator — useful when the agent is a product (e.g., a Claude integrator) |
| `tenant` | derived from a claim (e.g., `tenant_id` in the access token) | Bill the organization, not the individual |

The choice is per Lago plan, not per event. The metering worker reads the
plan's billing-identity field and maps. Defaults to `subject` to match the
"resource owner pays" convention from cloud APIs.

### What stays in the portfolio (not Lago's job)

- **Synchronous quota enforcement at request time** — Redis-backed counter
  consulted by `authorization-policy-service` or the inbound MCP authorization
  port. Lago reconciles periodically; it is not a request-path oracle.
- **Real-time cost gates** ("stop this agent at $50/day") — checked in the
  egress library before the upstream call (see the egress section in
  `agentic-posture.md`). Lago is the source of truth *after* the fact.
- **Per-call authorization decisions** — `authorization-policy-service`
  remains canonical.

### Discovery + metadata

`/.well-known/oauth-authorization-server` (ADR-0012) gains an optional
non-standard `billable_metrics_supported` extension naming the audit
`event_type` values the server currently emits to durable sinks. Lets RPs
and agents reason about what they will be billed for before requesting a
token.

## Consequences

### Positive

- **Zero parallel pipeline.** Accounting is a sink + a transform, not a
  second set of instrumentation. ADR-0015–0018 are already the data plane.
- **Open source, self-hostable billing engine.** No vendor lock-in on the
  invoicing layer. Lago can be replaced without touching the audit envelope.
- **Delegation-aware customer model.** The `act` chain + the
  billing-identity field on the plan lets us bill correctly for A2A
  scenarios without a separate accounting schema.

### Negative

- **The durable sink adds latency on the request path** for events where
  the sink is "required". Postgres `INSERT` p99 in Fly's `iad` region is
  ~3–8 ms; NATS JetStream sync ack is similar. Token issuance and tool
  invocation can absorb that; we pay it knowingly.
- **The metering worker is a new operational surface.** Lago credentials,
  dead-letter queues for transform failures, reconciliation runs. Reserved
  as Beyond-P2 in the architecture roadmap so we don't ship it before there
  is something to bill.
- **Plan migrations are now an audit-schema concern.** Changing the unit of
  a billable metric (e.g., from "tool call" to "tool call seconds") requires
  either a metric versioning strategy or a transform rewrite. The
  `schema_version` field on the audit envelope is the lever.

### Migration

Greenfield. No existing accounting to migrate. ADR-0018 ships first
(P0/P2 per the architecture roadmap); the durable sink is the additional
piece introduced here and lands when accounting is wired.

## Alternatives considered

- **Build a custom accounting service.** Reject — the engine is the hard
  part (plans, proration, refunds, dunning). Lago is mature and matches
  the open-source, self-hostable posture of the rest of the portfolio.
- **Stripe Metering (or any vendor SaaS).** Reject — closed source; vendor
  lock-in on the customer-of-record layer. Re-evaluate only if Lago
  proves operationally inadequate.
- **Embed cost tracking inside `authorization-policy-service`.** Reject —
  conflates authorization (request-path, synchronous, deny-by-default) with
  accounting (eventually consistent, never blocks). Two different problems,
  two different data shapes.
- **Skip durable audit and accept dropped accounting events.** Reject —
  defeats the purpose. The whole point is a defensible bill.

## References

- `architecture/docs/agentic-posture.md` — gap matrix and trigger list for
  when to wire metering
- ADR-0015 — `actor_type` / `agent_id` claims (the customer model upstream)
- ADR-0016 — Token Exchange / `act` chain (the delegation model that
  drives the billing-identity field)
- ADR-0017 — Rich Authorization Requests (per-call grants whose
  consumption Lago will eventually meter against)
- ADR-0018 — Agent audit event schema (the data plane that this ADR adds
  a durable sink onto)
- [Lago documentation](https://docs.getlago.com/) — event ingestion API,
  billable metrics, customer + subscription model
