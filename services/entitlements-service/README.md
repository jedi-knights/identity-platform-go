# entitlements-service

Owns the entitlement catalog (resources, bundles, plans) and per-account
subscription state. Answers "does this actor have this entitlement, now?"

## Status

**Scaffold in progress.** This directory currently contains only the
Postgres schema (E3-S2 / #155). The Go application arrives in follow-on
stories under Epic 3 (#140).

- [x] ADR-0028 — foundational design decisions ([`docs/adr/0028-*`](../../docs/adr/0028-entitlements-model.md))
- [x] Postgres schema + migrations (this PR)
- [ ] Seed initial catalog (#156)
- [ ] Hexagonal Go scaffold — domain / application / adapters / cmd
- [ ] HTTP + gRPC entitlement-check endpoints
- [ ] Auth-server outbound port for JWT claim enrichment

## Contents

- [`docs/schema.md`](./docs/schema.md) — ER diagram, table notes, index inventory
- [`internal/adapters/outbound/postgres/migrations/`](./internal/adapters/outbound/postgres/migrations/) — schema migrations (up + down)
- `go.mod` — module declaration; no Go code yet

## Foundational references

- **[ADR-0028](../../docs/adr/0028-entitlements-model.md)** — five design decisions this service is anchored on
- **[ADR-0027](../../docs/adr/0027-entitlements-enforces-quota-lago-prices.md)** — enforcement split (this service enforces; Lago prices)
- **[ADR-0019](../../docs/adr/0019-usage-accounting-and-billing.md)** — Lago/Stripe as billing engine

## Applying the schema

```bash
# Postgres URL (from Fly Managed Postgres attach, or a local dev instance):
export ENTITLEMENTS_DATABASE_URL="postgres://user:pass@host:5432/entitlements"

migrate -database "$ENTITLEMENTS_DATABASE_URL" \
  -path internal/adapters/outbound/postgres/migrations \
  up
```

Down migration is symmetric and drops in FK-safe order.

## Local development

Nothing runnable yet. When the Go scaffold arrives, the pattern will
follow the other services in this monorepo:

```
services/entitlements-service/
├── cmd/
│   └── main.go                     # Cobra entry
├── internal/
│   ├── domain/                     # Pure business types + rules
│   ├── application/                # Use-case services
│   ├── ports/                      # Inbound/outbound interfaces
│   ├── adapters/
│   │   ├── inbound/http/           # HTTP handlers
│   │   └── outbound/postgres/      # This dir — schema + repositories
│   └── container/                  # DI wiring via go-platform/container
```
