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
	issuer     string // when non-empty, tokens whose iss claim does not match are rejected (RFC 8725 §3.8)
}

// NewValidator returns a Validator using the given HMAC signing key.
// issuer may be empty — when set, tokens whose iss claim does not match are treated as inactive.
func NewValidator(signingKey []byte, issuer string) *Validator {
	return &Validator{signingKey: signingKey, issuer: issuer}
}

// Validate parses and validates a raw JWT string.
// Per RFC 7662 §2.2, any token validity failure must return {active: false}, not an error.
func (v *Validator) Validate(_ context.Context, raw string) (*domain.IntrospectionResult, error) {
	var (
		claims *jwtutil.Claims
		err    error
	)
	if v.issuer != "" {
		claims, err = jwtutil.ParseWithIssuer(raw, v.signingKey, v.issuer)
	} else {
		claims, err = jwtutil.Parse(raw, v.signingKey)
	}
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
		JTI:         claims.ID,
		Audience:    []string(claims.Audience),
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
