// Package entitlements is the root package placeholder for entitlements-service.
//
// The service is currently a scaffold — Postgres schema (000001 migration) and
// seed catalog (seeds/) landed under Epic 3 (#140). The Go application is
// still to come; when it does, it will follow the hexagonal layout used by
// other services in this monorepo (cmd → internal/{domain,application,ports,
// adapters,container}). See README.md and docs/adr/0028-entitlements-model.md.
//
// This file exists so `go test ./...` inside services/entitlements-service
// matches at least one package and exits 0 in CI. Delete once real packages
// are added under internal/.
package entitlements
