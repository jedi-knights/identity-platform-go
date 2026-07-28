# entitlements-service

Owns the entitlement catalog (resources, bundles, plans) and per-account
subscription state. Answers "does this actor have this entitlement, now?"

## Status

**Live Go service.** Personal-account creation is wired end-to-end
(`POST /accounts/personal`, idempotent, transactional owner-seat
creation, `account_created` audit event).

- [x] ADR-0028 — foundational design decisions ([`docs/adr/0028-*`](../../docs/adr/0028-entitlements-model.md))
- [x] Postgres schema + migrations (000001 catalog + 000002 personal-account keys)
- [x] Seed initial catalog
- [x] **Hexagonal Go scaffold — domain / application / adapters / cmd (this PR — #210)**
- [x] `POST /accounts/personal` — idempotent create with distinct 201/200 semantics
- [ ] Additional endpoints (seat management, entitlement lookup)
- [ ] Auth-server outbound port for JWT claim enrichment

## Layout

```
services/entitlements-service/
├── cmd/main.go                              # Cobra entry, HTTP server, tracing bootstrap
├── docs/schema.md                           # ER diagram + notes
├── seeds/                                   # Reference catalog seed (E3-S3)
└── internal/
    ├── domain/                              # Account, Seat, Role — pure business types
    ├── ports/                               # AccountRepository, SeatRepository
    ├── application/                         # AccountService.CreatePersonalAccount
    ├── observability/                       # Logger + audit emitter setup
    ├── config/                              # Viper-based config loader
    ├── container/                           # Dependency wiring (composition root)
    └── adapters/
        ├── inbound/http/                    # HTTP handler + router
        └── outbound/
            ├── memory/                      # In-memory repo (default)
            └── postgres/                    # pgx-backed repo + embedded migrations
```

## API

### `POST /accounts/personal`

Create or return the personal account for a user. Idempotent on
`user_id`.

Request:

```json
{ "user_id": "user-abc", "email": "u@example.com" }
```

Response (201 on create, 200 on idempotent replay):

```json
{
  "account_id": "…hex…",
  "billing_email": "u@example.com",
  "user_id": "user-abc",
  "created": true
}
```

- `201 Created` when this call created the account
- `200 OK` when an account with the same `user_id` already existed
- `400 Bad Request` on malformed body / missing required fields

### `GET /health`

Returns `{"status":"ok"}` at 200.

## Configuration

Env vars (all optional except in production):

| Var | Default | Purpose |
|-----|---------|---------|
| `ENTITLEMENTS_SERVER_HOST` | `0.0.0.0` | HTTP bind host |
| `ENTITLEMENTS_SERVER_PORT` | `8086` | HTTP bind port |
| `ENTITLEMENTS_LOG_LEVEL` | `info` | slog level |
| `ENTITLEMENTS_LOG_FORMAT` | `json` | log format |
| `ENTITLEMENTS_LOG_ENVIRONMENT` | `development` | environment tag |
| `ENTITLEMENTS_DATABASE_URL` | *(empty)* | Postgres DSN — when unset, in-memory adapter is used |
| `ENTITLEMENTS_AUDIT_DURABLE_DSN` | *(empty)* | Audit-event Postgres DSN (ADR-0018/0019) |
| `ENTITLEMENTS_AUDIT_SKIP_MIGRATION` | `false` | skip audit-schema CREATE TABLE |
| `ENTITLEMENTS_TRACING_ENABLED` | `false` | bootstrap OTel SDK |

## Running locally

In-memory (zero-dependency):

```bash
cd services/entitlements-service
go run ./cmd
# curl -X POST http://localhost:8086/accounts/personal \
#   -H 'Content-Type: application/json' \
#   -d '{"user_id":"u-1","email":"u1@x.com"}'
```

With Postgres:

```bash
docker run --rm -d --name ent-pg -e POSTGRES_PASSWORD=x -e POSTGRES_DB=ent -p 5432:5432 postgres:16
export ENTITLEMENTS_DATABASE_URL="postgres://postgres:x@localhost:5432/ent?sslmode=disable"
go run ./cmd    # runs 000001 + 000002 migrations at startup, then serves
```

## Testing

```bash
# Unit tests (no dependencies):
go test ./...

# Postgres integration tests (require a running Postgres):
docker run --rm -d --name ent-it-pg -e POSTGRES_PASSWORD=x -e POSTGRES_DB=ent -p 55440:5432 postgres:16
export ENTITLEMENTS_POSTGRES_TEST_URL="postgres://postgres:x@localhost:55440/ent?sslmode=disable"
go test -tags integration ./internal/adapters/outbound/postgres/...
```

The integration test exercises the concurrent-stampede path — 15
goroutines racing to upsert the same `user_id` all get the same
account ID back, verifying the partial-unique index protection.

## Foundational references

- **[ADR-0028](../../docs/adr/0028-entitlements-model.md)** — five design decisions this service is anchored on
- **[ADR-0027](../../docs/adr/0027-entitlements-enforces-quota-lago-prices.md)** — enforcement split (this service enforces; Lago prices)
- **[ADR-0019](../../docs/adr/0019-usage-accounting-and-billing.md)** — Lago/Stripe as billing engine
