# ADR-0019: Usage Accounting via the Audit Pipeline (Lago + Stripe)

**Status**: Accepted
**Date**: 2026-06-27

## Context

ADR-0018 establishes a single agent-audit event envelope and explicitly
permits emission to *drop on overflow* so the audit path can never fail the
underlying operation. That is the right posture for audit. It is the wrong
posture for accounting.

The portfolio now needs billing and metering as a **prerequisite** to
shipping additional agentic capabilities. The product requirements:

- **Per-actor usage counts** with the granularity already present in the
  ADR-0018 envelope (`actor_type`, `actor_id`, `subject_id`, `resource`,
  `action`, `attrs.duration_ms`, `attrs.tokens_in/out`,
  `attrs.upstream_cost_usd`, `act` chain depth for delegated calls).
- **At-least-once capture**. A dropped event is a missing line item.
- **Every event type is billable-capable.** Token issuance, token
  exchange, introspection, policy decisions, MCP tool calls, and DCR
  registrations are all candidate billable events. Which ones are actually
  *billed* is a configuration choice on the Lago side, not a code change.
- **À la carte capabilities AND configurable bundles.** Operators must be
  able to sell individual capabilities priced per use *and* package groups
  of capabilities as flat-rate or quota-bearing bundles, all configurable
  through admin without code changes.
- **Self-hosted billing engine.** The portfolio retains all of its own data;
  no SaaS vendor stores customer or usage records.
- **End user is the billed customer** (`subject_id` from the access token)
  by default, with a per-plan override available for tenant- or
  agent-operator-billed scenarios.
- **A customer / plan / invoice model.** Aggregating events is the easy
  half; mapping aggregates onto commercial terms (subscriptions, wallets,
  proration, refunds) is the hard half.
- **Real payment processing.** Card storage, charging, dunning, tax
  compliance, and receipts.

Building either the metering engine or the payment processor in-house is
unnecessary and operationally expensive. The right shape is two well-fit
open-source / vendor pieces with clean separation:

- **[Lago](https://www.getlago.com/)** — open source, self-hosted,
  event-ingestion-first, built for usage-based billing rather than seats.
  Owns billable metrics, plans, customers, subscriptions, invoices, prepaid
  wallets. Self-hosted on Fly.io so all customer + usage data stays inside
  the portfolio.
- **[Stripe](https://stripe.com/)** — payment processor only. Owns card
  storage (off our PCI scope), charge execution, tax (Stripe Tax),
  receipts, and the hosted customer-portal flows for card management. Lago
  has a native Stripe connector; no glue code in the metering worker.

The portfolio-wide context (gap analysis, trigger list, Phase B billing
readiness gate) lives in `architecture/docs/agentic-posture.md`. The
concrete deployment checklist lives in
`architecture/docs/billing-and-metering-setup.md`.

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

### Resource taxonomy (ADR-0018 extension)

The product requirements demand the ability to sell any of:

- **One MCP tool** (e.g., `get_standings`)
- **One MCP server** (e.g., everything `jk-mcp-nwsl` exposes)
- **One API endpoint** (e.g., `POST /oauth/token`)
- **One whole API** (e.g., everything auth-server exposes)
- **Bundles** combining any of the above

To make these SKU shapes addressable without code changes, ADR-0018's
audit envelope gains four structured fields that complement (do not
replace) the existing `resource` string. Emitters set them at the call
site; the metering shim forwards them straight through to Lago properties.

```jsonc
{
  // ... existing ADR-0018 envelope ...
  "resource": "tool:get_standings",   // human-readable URI (unchanged)

  // New structured fields — additions to ADR-0018
  "resource_kind": "tool",            // open enum — see table below
  "resource_id":   "get_standings",   // the leaf identifier
  "resource_parent": "jk-mcp-nwsl",   // the containing surface
  "resource_path":   "jk-mcp-nwsl/tool/get_standings"  // hierarchical path for prefix filters
}
```

The `resource_path` field is the key flexibility lever: Lago can filter
billable metrics by path prefix, so a single billable-metric definition
covers "all tools in `jk-mcp-nwsl`" without enumerating them. Adding a new
tool then requires zero billing-side change.

`resource_kind` is an **open enum** — new values can be added without
breaking emitters, since the metering shim treats all values opaquely and
Lago filters discriminate. The portfolio's initial enum:

| `resource_kind` | Meaning |
|---|---|
| `tool` | MCP tool (e.g., `get_standings`) |
| `server` | MCP server as a whole (typically appears as `resource_parent` on tool events; can also be billed directly via aggregate metrics) |
| `endpoint` | One HTTP endpoint (e.g., `POST /oauth/token`) |
| `api` | An entire API service (typically appears as `resource_parent` on endpoint events) |
| `token` | Token-lifecycle action (issue, exchange, introspect, revoke) |
| `application` | A web application session or use unit |
| `feature` | A feature within a web application (e.g., "pdf_export", "ai_search") |

Additions to the enum require zero shim or audit-envelope changes — only an
operator-side Lago filter update if the new kind is to be billed
distinctly.

SKU shape recipes:

| SKU shape | Typical filter | Example billable metric |
|---|---|---|
| One tool | `resource_path = "jk-mcp-nwsl/tool/get_standings"` | "Standings lookups" |
| Entire MCP server | `resource_parent = "jk-mcp-nwsl"` | "NWSL MCP server use" |
| One endpoint | `resource_path = "auth-server/endpoint/POST /oauth/token"` | "Token issuance" |
| Entire API | `resource_parent = "auth-server"` | "Auth-server use" |
| Token actions | `resource_kind = "token"` AND `action = "issue"` | "Tokens issued" |
| Web app session | `resource_kind = "application"` AND `resource_id = "billpayer"` | "Bill-payer app use" |
| Single feature | `resource_path = "billpayer/feature/pdf_export"` | "PDF export usage" |
| All features in an app | `resource_kind = "feature"` AND `resource_parent = "billpayer"` | "Bill-payer feature use" |
| Combined (bundle) | a Lago **plan** wrapping multiple metrics | "Starter bundle" |

ADR-0018's `event_type` registry stays. The new fields are added to every
emitter the same way ADR-0015's `actor_type` and `agent_id` were — additive,
optional during migration, required for new event types after the extension
lands.

### Metering worker — property pump, not SKU logic

A new out-of-process worker (in its own repo, `jk-metering`) subscribes to
the durable sink and transforms each audit event into **one** Lago event.
The transformation is intentionally generic:

- Every audit event becomes a Lago event with `code = "usage"`. No
  per-event-type Lago codes. **All discrimination happens via Lago filters
  on properties, not via event codes.** Adding a new event type, a new
  resource, a new tool, or a new endpoint requires zero shim change.
- All ADR-0018 envelope fields plus the resource taxonomy plus everything
  in `attrs` map 1:1 to Lago event `properties`. The shim is a JSON
  flattener, nothing more.
- `external_subscription_id` is resolved by the worker via Lago's customer
  API, keyed on the audit event's billing-identity claim (see "Billing
  identity" below). The shim caches resolutions for a configurable TTL.

```
audit_event                              lago_event
─────────────────────                    ────────────────────
event_id: 01J7M3X9...           ───►     transaction_id: 01J7M3X9...
event_type: tool_invoked                 external_subscription_id: <resolved>
service: jk-mcp-nwsl                     code: usage
actor_type: agent                        timestamp: <event.timestamp>
actor_id: agent-claude-abc               properties:
subject_id: user-omar                    ▸ event_type: tool_invoked
resource: tool:get_standings             ▸ service: jk-mcp-nwsl
resource_kind: tool                      ▸ actor_type: agent
resource_id: get_standings               ▸ actor_id: agent-claude-abc
resource_parent: jk-mcp-nwsl             ▸ subject_id: user-omar
resource_path: jk-mcp-nwsl/tool/get_…    ▸ resource: tool:get_standings
attrs.duration_ms: 142                   ▸ resource_kind: tool
attrs.upstream_cost_usd: 0.0             ▸ resource_id: get_standings
                                         ▸ resource_parent: jk-mcp-nwsl
                                         ▸ resource_path: jk-mcp-nwsl/tool/get_…
                                         ▸ duration_ms: 142
                                         ▸ upstream_cost_usd: 0.0
```

Idempotency: Lago dedupes by `transaction_id`, which we map 1:1 to the
audit `event_id` (ULID, globally unique). Replays and reconciliation runs
are safe and lossless.

Repo separation: the worker lives in `jk-metering`, isolating Lago
credentials and keeping the auth-server's responsibility tight (issue
tokens, emit events).

### Product catalog — bundles + à la carte, configured in Lago

The catalog is **data, not code**. Operators model SKUs through Lago's
admin UI / API and never need a release to launch a new product.

| Lago primitive | Role in this portfolio |
|---|---|
| **Billable metric** | A SKU. Defined by an aggregation (`count`, `sum`, `unique_count`, `latest`, `max`) over the single `code = "usage"` event, filtered by any combination of properties (`service`, `resource_kind`, `resource_parent`, `resource_path`, `event_type`, `actor_type`). |
| **Plan** | A bundle — fixed-fee + included quotas + per-metric overage prices. Or a pay-as-you-go shape: no fixed fee, per-unit prices on selected metrics. |
| **Subscription** | A customer's commitment to a plan. Customer = end user (`subject_id`) by default. |
| **Charge** | The pricing model on a billable metric within a plan: `standard` (per-unit), `graduated`, `package`, `volume`, `percentage`. |
| **Wallet** | Prepaid credit balance. Useful for "buy $50 of capacity" SKUs. |
| **Coupon** | Promotional discount on a plan or metric. |

Recipes for the requested SKU shapes:

- **À la carte tool** → billable metric filtered to one
  `resource_path`, attached to a pay-as-you-go plan with a `standard`
  charge.
- **Entire MCP server** → billable metric filtered to
  `resource_parent = "jk-mcp-nwsl"`, attached to a flat-fee plan
  (subscription) or a tiered plan with included calls.
- **Per-endpoint** → billable metric filtered to one `resource_path`
  under `service = "auth-server"`.
- **Entire API** → billable metric filtered to
  `resource_parent = "auth-server"`.
- **Bundle** → one plan with multiple billable metrics, each priced
  independently (or zero-priced inside the bundle and metered for fair-use
  caps). Add or remove metrics from the bundle in Lago admin; no deploy.

The flexibility commitment: **adding a new tool, new endpoint, new
resource kind, or new bundle shape never requires a code change in the
auth-server, MCP servers, audit pipeline, or metering worker.** Either the
new emitter is already covered by an existing taxonomy field (most cases)
or the operator adds a new value to `resource_kind` and a matching Lago
filter (rare cases). The shim does not know what an SKU is.

### Web applications and feature-level billing

Backend services (auth-server, MCP servers, policy service) emit audit
events in-process via `go-platform/audit`. Web applications cannot — they
run client-side (SPAs) or in deployments that we don't co-own. To support
billing for **web application use** and **feature use within a web
application**, the portfolio introduces a thin server-side **metering
ingestion endpoint**:

```
POST /metering/events
Authorization: Bearer <access_token>
{
  "event_type": "feature_used",
  "resource_kind": "feature",
  "resource_id": "pdf_export",
  "resource_parent": "billpayer",
  "resource_path": "billpayer/feature/pdf_export",
  "attrs": { "size_kb": 47, "duration_ms": 312 }
}
```

The endpoint:

- **Authenticates** the bearer token (RS256 via JWKS — same as MCP servers).
- **Authorizes** the emission against `authorization-policy-service` so a
  compromised client can't poison the meter (only a token with the right
  scope can emit events for a given `resource_parent`).
- **Injects** the trusted fields (`actor_type`, `actor_id`, `subject_id`,
  `service`, `trace_id`, `event_id`, `timestamp`) from the token + server
  context, ignoring whatever the client claims for those fields.
- **Emits** through the same `go-platform/audit` durable sink as the rest
  of the portfolio. From there, the metering shim treats web-app events
  identically to backend events — same Lago `code = "usage"`, same property
  pump, same SKU filters.

Two patterns for client integration:

1. **Server-rendered web apps** call `go-platform/audit.Emit()` directly
   in their handlers, no HTTP hop needed. Use this when the app and the
   audit sink share a deployment boundary.
2. **SPAs / mobile / third-party UIs** call `POST /metering/events`
   from their backend-for-frontend or directly with a user-scoped access
   token. Use this when the app cannot import the audit package.

The endpoint ships in a new lightweight service (`jk-metering-ingest`) or
folds into `auth-server` — exact home decided at implementation time; the
contract is the same either way.

**Anti-spam guard.** The endpoint enforces a per-token rate limit at the
gateway (via `jk-api-gateway`) plus a server-side cap on
`attrs` payload size. Authorization-policy scopes (e.g.,
`metering:emit:billpayer`) gate which `resource_parent` values a token may
emit for.

### Payment processing — Stripe via Lago's connector

[Stripe](https://stripe.com/) is the payment processor. Lago has a native
Stripe connector that takes care of customer creation, invoice push, and
payment-status webhook handling. Specifically:

- **PCI scope** — card data never touches the portfolio. Stripe stores
  cards; users add them through Stripe Checkout or the Stripe Customer
  Portal.
- **Customer mapping** — Lago creates a corresponding Stripe customer on
  first subscription, linking the two via Lago's `external_customer_id`
  (always set to the identity-platform `subject_id`).
- **Invoice flow** — Lago generates an invoice at the end of the billing
  cycle, pushes to Stripe via the connector, Stripe charges the customer's
  default payment method, and webhook results return to Lago which marks
  the invoice paid / failed.
- **Tax** — Stripe Tax is enabled on the Stripe account; Lago passes
  taxable line items through. Self-hosted Lago does not need to know about
  the user's tax jurisdiction; Stripe handles it.
- **Refunds, disputes, dunning** — managed in Stripe; Lago reflects the
  final status.
- **Customer portal** — Stripe's hosted portal is the canonical UI for
  managing cards, viewing invoices, and downloading receipts. We do not
  build our own.

### Billing portal — folded into login-ui

Plan selection lives in `login-ui` (ADR-0011), alongside sign-in and
consent. The new flows:

| Flow | Where | What it does |
|---|---|---|
| **Plan selection** | `login-ui` | Lists active plans from Lago's plans API, lets the user pick. Plans are not hardcoded in login-ui. |
| **Card collection** | Stripe Checkout (redirect) | login-ui creates a Stripe Checkout session via Lago's connector and redirects. |
| **Subscription provisioning** | Stripe webhook → Lago | On `checkout.session.completed`, Lago creates the subscription. |
| **Manage subscription** | Stripe Customer Portal | login-ui exposes a link; user manages cards and views invoices in Stripe's hosted UI. |

login-ui treats Lago as just another outbound dependency (port + adapter,
mirroring auth-server's `UserAuthenticator`). Adding a plan or pricing
change in Lago is reflected immediately on the plan-selection page.

### Billing identity (who pays)

Token exchange (ADR-0016) and RAR (ADR-0017) introduce delegation chains
where the `actor` (immediate caller) and `subject` (resource owner) differ.
The portfolio default and explicit policy:

| Plan billing-identity field | Lago `external_subscription_id` | Use case |
|---|---|---|
| `subject` **(portfolio default)** | `subject_id` | The end user owns the cost — the requested default. |
| `actor` | `actor_id` | Bill the agent operator (e.g., a Claude integrator product). |
| `tenant` | derived from a claim (e.g., `tenant_id`) | Bill the organization. |

The choice is per Lago plan, not per event. The metering worker reads the
plan's billing-identity field and maps. Defaults to `subject` per
operator requirement.

### Adding new billable surfaces — the flexibility commitment

Billing will change over time as new capabilities are added. The design
above is structured so adding revenue surface is a configuration task in
Lago, not a code change in the portfolio. The decision tree:

| New billable surface | What an operator does |
|---|---|
| **New tool on an existing MCP server** | Nothing on the billing side — existing per-server billable metrics already capture it via `resource_parent`. To bill it individually: add a new Lago billable metric filtered to its `resource_path`, attach to a plan. |
| **New endpoint on an existing API** | Same — covered by per-API metric via `resource_parent`. Individual pricing = one new Lago metric. |
| **New MCP server** | Standard hexagonal scaffolding (one new repo). The audit envelope is identical; the only billing-side work is one Lago metric per new SKU shape. |
| **New web application** | Wire the metering ingestion endpoint (or import `go-platform/audit`). One Lago metric per SKU shape. |
| **New feature in an existing web app** | One emitter call in the feature handler. Zero billing-side work if covered by a "all features" metric; one new Lago metric if priced individually. |
| **New `resource_kind`** | Add the value to the enum (documentation only — the shim is opaque). One Lago metric per SKU shape. |
| **New pricing model on an existing surface** | Lago admin only — switch charge model (`standard` → `graduated`, etc.), adjust prices, no deploy. |
| **New bundle** | Lago admin only — create a plan combining existing billable metrics. |
| **Promotion / discount** | Lago admin — issue a coupon. |
| **Free trial** | Lago admin — plan-level trial period or wallet credit. |

The **code-change boundary**: anything that requires emitting a new field
or a structurally different event shape touches `go-platform/audit` and
its emitters. Everything else — product catalog, pricing, packaging,
discounts — is operator configuration in Lago.

### What stays in the portfolio (not Lago / Stripe's job)

- **Synchronous quota enforcement at request time** — Redis-backed counter
  consulted by `authorization-policy-service` or the inbound MCP authorization
  port. Lago reconciles periodically; it is not a request-path oracle.
- **Real-time cost gates** ("stop this agent at $50/day") — checked in the
  egress library before the upstream call. Lago is the source of truth
  *after* the fact.
- **Per-call authorization decisions** — `authorization-policy-service`
  remains canonical.

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

- **Zero parallel pipeline.** Accounting is a sink + a generic transform,
  not a second set of instrumentation. ADR-0015–0018 are already the data
  plane.
- **Self-hosted, open-source billing engine.** All customer and usage data
  stays inside the portfolio. Lago can be replaced without touching the
  audit envelope.
- **Stripe handles the hardest parts (cards, tax, dunning) without us
  storing card data.** PCI scope contained; SAQ-A is the maximum compliance
  surface.
- **Delegation-aware customer model.** The `act` chain + the
  billing-identity field on the plan lets us bill correctly for A2A
  scenarios without a separate accounting schema.
- **Catalog-as-data.** Adding a tool, an endpoint, a feature, a web app, a
  new bundle, or a new pricing model does not require a portfolio release.
  The flexibility commitment table makes the code-change boundary explicit.
- **One `usage` event code in Lago, discriminated by filters.** No SKU
  enumeration in code; new revenue surfaces are operator configuration.

### Negative

- **The durable sink adds latency on the request path** for events where
  the sink is "required". Postgres `INSERT` p99 in Fly's `iad` region is
  ~3–8 ms; NATS JetStream sync ack is similar. Token issuance and tool
  invocation can absorb that; we pay it knowingly.
- **Two new operational surfaces.** The metering worker (`jk-metering`)
  and the Lago deployment itself (Lago + Postgres + Redis on Fly).
  Operators run an additional Postgres for Lago, separate from the
  identity-platform databases (Lago's schema is its own concern).
- **Stripe is a vendor.** The processor is closed source by necessity.
  We accept Stripe as the payment-rails dependency; the Lago↔Stripe
  connector is the swap point if we ever change processors.
- **Plan migrations are now an audit-schema concern.** Changing the unit
  of a billable metric (e.g., from "tool call" to "tool call seconds")
  requires either a metric versioning strategy or a transform rewrite.
  The `schema_version` field on the audit envelope is the lever.
- **Lago becomes a critical-path dependency for plan-selection.** If Lago
  is down, login-ui's plan-selection page degrades. Mitigation: short-TTL
  cache of plan listings in login-ui; sign-in itself is unaffected.

### Migration

Greenfield. No existing accounting to migrate. Sequenced behind a **Phase B
— Billing readiness** gate in `architecture/docs/agentic-posture.md`
before any additional agentic capabilities are shipped, per the portfolio
priority. Implementation order:

1. Deploy Lago on Fly.io (Postgres + Redis sidecars).
2. Configure Stripe account + Lago↔Stripe connector.
3. Ship `go-platform/audit` with both `stderr_json` and `durable` sinks.
4. Extend ADR-0018 emitters with the new resource taxonomy fields.
5. Stand up `jk-metering` and verify Lago event ingestion.
6. Add `/metering/events` ingestion endpoint for web apps.
7. Wire login-ui plan selection + Stripe Checkout.
8. Define the first billable metrics + the Free / Starter / Pro plans in
   Lago. End-to-end smoke from sign-up → plan pick → card on file →
   tool call → invoice → charge → marked paid.

The concrete checklist lives in
`architecture/docs/billing-and-metering-setup.md`.

## Alternatives considered

- **Build a custom accounting service.** Reject — the engine is the hard
  part (plans, proration, refunds, dunning). Lago is mature and matches
  the self-hosted, open-source posture of the rest of the portfolio.
- **Stripe Billing alone (no Lago).** Reject — Stripe Billing's
  usage-based-pricing primitives are weaker than Lago's (limited filter
  composability; per-product complexity). And it puts customer + usage
  records in Stripe's cloud, violating the self-hosted-data requirement.
- **OpenMeter, Metronome, Orb, Octane.** OpenMeter is the closest peer.
  Picked Lago for maturity of the Stripe connector, plan / wallet /
  coupon coverage, and a more advanced filtered-metric model. Re-evaluate
  if Lago hits operational limits.
- **Embed cost tracking inside `authorization-policy-service`.** Reject —
  conflates authorization (request-path, synchronous, deny-by-default) with
  accounting (eventually consistent, never blocks). Two different problems,
  two different data shapes.
- **Skip durable audit and accept dropped accounting events.** Reject —
  defeats the purpose. The whole point is a defensible bill.
- **Per-event-type Lago codes (e.g., `tool_invoked`, `token_issued`).**
  Reject — couples Lago configuration to the event-type registry. Single
  `usage` code with filter-based discrimination keeps the catalog free to
  evolve.

## References

- `architecture/docs/agentic-posture.md` — gap matrix, Phase B billing
  readiness gate, ingress/egress, usage accounting
- `architecture/docs/billing-and-metering-setup.md` — concrete deployment
  + configuration checklist
- ADR-0015 — `actor_type` / `agent_id` claims (the customer model upstream)
- ADR-0016 — Token Exchange / `act` chain (the delegation model that
  drives the billing-identity field)
- ADR-0017 — Rich Authorization Requests (per-call grants whose
  consumption Lago meters against)
- ADR-0018 — Agent audit event schema (the data plane this ADR adds a
  durable sink and a resource taxonomy onto)
- [Lago documentation](https://docs.getlago.com/) — event ingestion API,
  billable metrics, filters, customer + subscription model, Stripe connector
- [Stripe Checkout + Customer Portal docs](https://stripe.com/docs/payments/checkout)
  — hosted card collection and self-service management
- [Stripe Tax](https://stripe.com/docs/tax) — automatic tax handling at
  invoice time
