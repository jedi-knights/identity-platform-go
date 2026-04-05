# ADR-0005: Adapter Scalability Contract via Compile-Time Interface Checks

**Status**: Accepted  
**Date**: 2026-04-05

## Context

The identity platform uses the Ports-and-Adapters (Hexagonal) architecture. Each service defines repository interfaces in `internal/domain/` and ships one or more adapter implementations in `internal/adapters/outbound/`. The current set of adapters is all in-memory (development/test scaffolding), but the design explicitly anticipates future adapters backed by PostgreSQL, Redis, or other durable stores.

The risk is silent drift: a domain interface could gain a new method and the compiler would only report the missing implementation at the call site that performs the concrete → interface conversion, which may be inside `container.go` or a test helper far removed from the adapter itself. This makes interface non-compliance easy to miss during development and creates confusing error messages.

A secondary concern is horizontal scalability. The in-memory adapters store state in process-local maps guarded by `sync.RWMutex`. Any replica of a service would have its own independent copy of that state, making multi-instance deployments functionally incorrect without an external state store. This is a known, intentional limitation during the reference implementation phase.

## Decision

1. **Every memory adapter file that implements a domain repository interface must include a blank-identifier compile-time check immediately before the struct declaration:**

   ```go
   var _ domain.XRepository = (*XRepository)(nil)
   ```

   This pattern (documented in Effective Go under "Blank Identifier") causes the compiler to verify full interface satisfaction at the declaration site rather than at first use. The error message points directly to the adapter file, not the call site.

2. **This convention applies to all adapters** — not just in-memory ones. When future PostgreSQL or Redis adapters are added, they must carry the same check. The rule is enforced by code review and by the `go-conventions` coding standard in `CLAUDE.md`.

3. **The in-memory adapters are explicitly documented as single-instance only.** They are suitable for local development and unit testing. They must not be used in any horizontally-scaled deployment without replacement by a durable, shared-state adapter (e.g., PostgreSQL, Redis, DynamoDB). This constraint is visible in:
   - The compile-time check file (it is the swap point: replace the type and the check catches any missing methods)
   - `docs/adr/0004-in-memory-persistence-for-reference.md`
   - `CLAUDE.md` under the "Intentional Design Decisions" section

## Files Changed

| File | Check Added |
|------|-------------|
| `services/auth-server/.../memory/token_repo.go` | `var _ domain.TokenRepository = (*TokenRepository)(nil)` |
| `services/auth-server/.../memory/client_repo.go` | `var _ domain.ClientRepository = (*ClientRepository)(nil)` |
| `services/client-registry-service/.../memory/client_repo.go` | `var _ domain.ClientRepository = (*ClientRepository)(nil)` |
| `services/identity-service/.../memory/user_repo.go` | `var _ domain.UserRepository = (*UserRepository)(nil)` |
| `services/example-resource-service/.../memory/resource_repo.go` | `var _ domain.ResourceRepository = (*ResourceRepository)(nil)` |
| `services/authorization-policy-service/.../memory/policy_repo.go` | `var _ domain.PolicyRepository = (*PolicyRepository)(nil)` + `var _ domain.RoleRepository = (*RoleRepository)(nil)` |

## Consequences

**Positive**

- Interface drift is caught at compile time, at the adapter declaration site.
- Swapping an adapter implementation (e.g., replacing the in-memory `TokenRepository` with a PostgreSQL-backed one) is safe: the check immediately flags any methods that still need to be implemented.
- The pattern is self-documenting — a reader can see exactly which domain interface the type is intended to satisfy.

**Negative / Trade-offs**

- Minor boilerplate: one line per interface per adapter file.
- The in-memory adapters are still single-instance. The compile-time check does not itself address the scalability gap — it only makes the swap point explicit. Durable adapters must be written and wired before multi-replica deployments are supported.

## Alternatives Considered

- **Interface embedding in the struct**: Go does not support embedding an interface definition in a struct for compile-time checking in the same idiomatic way.
- **Relying solely on container.go type assignments**: These checks exist but are at the wiring site, one level of indirection away from the implementation. They are useful but not sufficient — the blank-identifier check is a stronger, co-located signal.
