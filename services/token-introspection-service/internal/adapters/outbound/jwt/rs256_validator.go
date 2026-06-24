package jwt

import (
	"context"

	"github.com/jedi-knights/go-platform/jwtutil"

	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
)

// Compile-time interface check — catches drift if domain.TokenValidator changes.
var _ domain.TokenValidator = (*RS256Validator)(nil)

// RS256Validator parses and validates RS256-signed JWTs using a KeySource
// (typically backed by a JWKS HTTP client) to resolve verification keys.
//
// Per RFC 7662 §2.2, any token-validation failure — bad signature, expired,
// wrong issuer, unknown kid, malformed — returns an inactive IntrospectionResult
// rather than an error. The validator only returns an error when called
// before construction (impossible by design) or when context is cancelled
// inside the keyfunc.
type RS256Validator struct {
	keySource jwtutil.KeySource
	issuer    string // when non-empty, tokens whose iss claim does not match are inactive (RFC 8725 §3.8)
}

// NewRS256Validator wires the validator to a KeySource. Nil keySource is a
// programmer error.
func NewRS256Validator(keySource jwtutil.KeySource, issuer string) *RS256Validator {
	if keySource == nil {
		panic("NewRS256Validator: keySource must not be nil")
	}
	return &RS256Validator{keySource: keySource, issuer: issuer}
}

// Validate parses the raw JWT as RS256. Any validation failure produces
// {Active: false, ...} per RFC 7662 §2.2 — there is no infrastructure-vs-token
// distinction here; all jwtutil errors are treated as "token not valid."
func (v *RS256Validator) Validate(ctx context.Context, raw string) (*domain.IntrospectionResult, error) {
	claims, err := jwtutil.ParseRS256(ctx, raw, v.keySource)
	if err != nil {
		return &domain.IntrospectionResult{Active: false}, nil
	}
	if v.issuer != "" && claims.Issuer != v.issuer {
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
