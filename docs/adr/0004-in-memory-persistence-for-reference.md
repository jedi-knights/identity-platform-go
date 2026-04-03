# ADR-0004: Use In-Memory Persistence for Reference Implementation

## Status
Accepted

## Context
This is a reference implementation demonstrating architectural patterns. We need persistence without requiring running databases in development.

## Decision
All services use in-memory repositories (protected by `sync.RWMutex`) as their outbound adapters. Production implementations would replace these adapters with PostgreSQL, Redis, or other appropriate stores without touching the domain or application layers.

## Consequences
- Zero external dependencies required to run any service locally.
- Data is lost on restart (acceptable for reference implementation).
- Adding production persistence requires only implementing new outbound adapters.
- Thread-safe implementation ensures correct behavior under concurrent access.
