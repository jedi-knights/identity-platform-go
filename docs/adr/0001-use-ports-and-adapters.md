# ADR-0001: Use Ports and Adapters Architecture

## Status
Accepted

## Context
We need a consistent architectural pattern that enforces separation of concerns, enables testability, and prevents infrastructure concerns from leaking into business logic.

## Decision
Adopt the Ports and Adapters (Hexagonal Architecture) pattern for all services. The dependency direction is strictly enforced: `domain → application → ports → adapters`.

- **Domain layer**: Pure business models and repository interfaces. No framework imports.
- **Application layer**: Business logic. Depends only on domain interfaces.
- **Ports layer**: Defines inbound and outbound port interfaces.
- **Adapters layer**: Implements ports using concrete technologies (HTTP, databases, JWT, etc.).

## Consequences
- All business logic is framework-agnostic and easily testable in isolation.
- Infrastructure can be swapped without modifying business logic.
- Clear boundaries prevent accidental coupling.
- Some additional boilerplate for adapter/port definitions.
