package jwt

import (
	"context"

	"github.com/ocrosby/identity-platform-go/libs/jwtutil"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
)

// Compile-time interface check — catches drift if domain.TokenValidator changes.
var _ domain.TokenValidator = (*Validator)(nil)

// Validator parses and validates JWT tokens using HMAC signing.
type Validator struct {
	signingKey []byte
}

// NewValidator returns a Validator using the given HMAC signing key.
func NewValidator(signingKey []byte) *Validator {
	return &Validator{signingKey: signingKey}
}

// Validate parses and validates a raw JWT string.
// Per RFC 7662 §2.2, any token validity failure must return {active: false}, not an error.
func (v *Validator) Validate(_ context.Context, raw string) (*domain.IntrospectionResult, error) {
	claims, err := jwtutil.Parse(raw, v.signingKey)
	if err != nil {
		return &domain.IntrospectionResult{Active: false}, nil
	}

	result := &domain.IntrospectionResult{
		Active:      true,
		Subject:     claims.Subject,
		ClientID:    claims.ClientID,
		Scope:       claims.Scope,
		TokenType:   "Bearer",
		Issuer:      claims.Issuer,
		Roles:       claims.Roles,
		Permissions: claims.Permissions,
	}
	if claims.ExpiresAt != nil {
		result.ExpiresAt = claims.ExpiresAt.Unix()
	}
	if claims.IssuedAt != nil {
		result.IssuedAt = claims.IssuedAt.Unix()
	}
	return result, nil
}
