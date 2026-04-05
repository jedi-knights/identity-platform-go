package application

import (
	"context"
	"fmt"

	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
)

// IntrospectionService implements RFC 7662 token introspection.
// It first validates the JWT signature and claims, then optionally checks the revocation store.
type IntrospectionService struct {
	validator  domain.TokenValidator
	revocation domain.RevocationChecker // nil = no revocation check (local dev fallback)
}

// NewIntrospectionService returns an IntrospectionService wired with the given validator and optional revocation checker.
// When revocation is nil, revoked tokens will appear active until their JWT expiry — acceptable for local development.
func NewIntrospectionService(validator domain.TokenValidator, revocation domain.RevocationChecker) *IntrospectionService {
	return &IntrospectionService{validator: validator, revocation: revocation}
}

// Introspect validates the raw JWT and, if a revocation store is configured, confirms the token
// has not been revoked. Per RFC 7662 §2.2 any infrastructure error is treated as revocation (fail closed).
func (s *IntrospectionService) Introspect(ctx context.Context, raw string) (*domain.IntrospectionResult, error) {
	result, err := s.validator.Validate(ctx, raw)
	if err != nil {
		return nil, err
	}
	if !result.Active {
		return result, nil
	}
	// If a revocation store is configured, confirm the token is still present in Redis.
	// auth-server deletes the key on revocation, so a missing key means the token was revoked.
	if s.revocation != nil {
		active, err := s.revocation.IsActive(ctx, raw)
		if err != nil {
			// Propagate so the handler can log with trace ID context.
			// The handler translates this to {active:false} per RFC 7662 §2.2 (fail closed).
			return nil, fmt.Errorf("revocation check: %w", err)
		}
		if !active {
			return &domain.IntrospectionResult{Active: false}, nil
		}
	}
	return result, nil
}
