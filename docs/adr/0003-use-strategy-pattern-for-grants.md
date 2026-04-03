# ADR-0003: Use Strategy Pattern for OAuth2 Grant Type Handling

## Status
Accepted

## Context
OAuth2 defines multiple grant types (client_credentials, authorization_code, refresh_token, etc.). We need an extensible way to add new grant types without modifying existing code.

## Decision
Implement the Strategy pattern for grant type handling. Each grant type is a `GrantStrategy` satisfying a common interface. A `GrantStrategyRegistry` holds all strategies and routes requests to the appropriate one.

```go
type GrantStrategy interface {
    Handle(ctx context.Context, req GrantRequest) (*GrantResponse, error)
    Supports(gt GrantType) bool
}
```

## Consequences
- New grant types can be added by implementing a new strategy (Open/Closed Principle).
- Each strategy is independently testable.
- Negligible routing overhead at this scale.
