# ADR-0027: Entitlements-service enforces quotas; Lago only prices

**Status**: Accepted
**Date**: 2026-07-27

## Context

ADR-0019 established Lago + Stripe as the self-hosted billing engine. Epic 2
(#139) ships the initial Touchline plan catalog (E2-S2 / #152) with three
plans:

- `touchline-free` — 3 match reviews per month, hard cap
- `touchline-coach` — unlimited matches, single-seat
- `touchline-club` — unlimited matches, 10-seat allowance

Epic 3 (#139 metering) will define a `matches` billable metric for
usage tracking. That creates two candidate homes for **enforcement** of
the "3 matches/mo hard cap on Free":

1. **Lago-native**: attach a graduated `charges` block to the Free plan
   referencing the `matches` metric — 0–3 free, 4+ blocked (or overage-priced)
2. **Auth-layer**: `entitlements-service` (planned) reads
   `plan.metadata.match_quota` and denies the 4th match request at token
   introspection / policy-check time

Seat enforcement has only one candidate — Lago has no seat concept — so
seats are `entitlements-service`'s problem regardless.

## Decision

**`entitlements-service` enforces every access decision. Lago prices,
invoices, and (Epic 3 onward) reports usage.**

Concretely:

- Plan `metadata.match_quota` and `metadata.seat_allowance` are the
  enforcement contract. `entitlements-service` reads them at auth-check
  time.
- The `matches` billable metric (Epic 3) enables usage dashboards and
  future overage pricing. It is not wired into the Free plan as a
  graduated `charges` block for the purpose of hard-capping.
- The plan JSONs at `infra/lago/plans/*.json` do not grow a `charges`
  block for hard-cap enforcement when Epic 3 lands.

## Rationale

- **One enforcement point.** `entitlements-service` exists for role gates
  and feature flags regardless of billing. Splitting quota enforcement
  between auth-layer and Lago's billing engine creates two accounting
  paths for one decision — a divergence bug waiting to happen.
- **Lago's meter is designed for overage billing.** Graduated `charges`
  models "free 0-3, then $0.50 each" cleanly; it models "free 0-3, then
  hard block" awkwardly. Using it for the awkward case is fighting the
  tool.
- **Traceability.** "Why was this request denied?" resolves to one code
  path in `entitlements-service`. Debugging joint auth-and-billing denial
  is exactly the class of problem this decision prevents.
- **Seats already live in entitlements.** Splitting seats there and
  quotas in Lago would split one mental model along an axis the domain
  does not care about.

## Consequences

**Kept:**
- Plans in `infra/lago/plans/*.json` retain `metadata.match_quota`,
  `metadata.seat_allowance`, `metadata.entitlements_tier`
- `entitlements-service` must be able to resolve a subject's subscription →
  plan → metadata at auth-check time (either via Lago API lookup or a
  cached mirror updated by Lago webhook)

**Rejected:**
- No graduated `charges` block on Free for hard-cap enforcement, even
  after Epic 3's `matches` metric lands
- No dual-enforcement (Lago blocks *and* entitlements blocks) — one
  enforcement point only

**Follow-on decisions deferred:**
- Overage pricing on any plan (e.g. "3 free matches, then $0.99 each") is
  when a `charges` block becomes appropriate — that is billing, not
  enforcement. Revisit if/when overage pricing enters the product.
- Whether `entitlements-service` reads Lago live or maintains its own
  cached plan-metadata mirror. Lean toward mirror for auth-check latency;
  decide at `entitlements-service` design time.

## Related

- ADR-0018: Agent audit event schema (source of the usage counts)
- ADR-0019: Usage accounting via the audit pipeline (Lago + Stripe)
- Issue #152 (E2-S2): plan catalog PR where this decision surfaced
- Epic 3 (#139): billable metric that must not be misused for enforcement
