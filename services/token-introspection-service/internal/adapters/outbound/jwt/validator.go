package jwt

import (
	"context"

	gojwt "github.com/golang-jwt/jwt/v5"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
)

type jwtClaims struct {
	gojwt.RegisteredClaims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"` // RFC 9068 §2.2.3.1: space-delimited string
}

// Validator parses and validates JWT tokens using HMAC signing.
type Validator struct {
	signingKey []byte
}

func NewValidator(signingKey []byte) *Validator {
	return &Validator{signingKey: signingKey}
}

func (v *Validator) keyFunc(t *gojwt.Token) (any, error) {
	if _, ok := t.Method.(*gojwt.SigningMethodHMAC); !ok {
		return nil, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid signing method")
	}
	return v.signingKey, nil
}

func claimsToResult(claims *jwtClaims) *domain.IntrospectionResult {
	result := &domain.IntrospectionResult{
		Active:    true,
		Subject:   claims.Subject,
		ClientID:  claims.ClientID,
		Scope:     claims.Scope,
		TokenType: "Bearer",
		Issuer:    claims.Issuer,
	}
	if claims.ExpiresAt != nil {
		result.ExpiresAt = claims.ExpiresAt.Unix()
	}
	if claims.IssuedAt != nil {
		result.IssuedAt = claims.IssuedAt.Unix()
	}
	return result
}

// Validate parses and validates a raw JWT string.
// Per RFC 7662 §2.2, any token validity failure must return {active: false}, not an error.
func (v *Validator) Validate(_ context.Context, raw string) (*domain.IntrospectionResult, error) {
	token, err := gojwt.ParseWithClaims(raw, &jwtClaims{}, v.keyFunc)
	if err != nil {
		return &domain.IntrospectionResult{Active: false}, nil
	}

	if !token.Valid {
		return &domain.IntrospectionResult{Active: false}, nil
	}

	claims, ok := token.Claims.(*jwtClaims)
	if !ok {
		// This should never happen since we passed &jwtClaims{} to ParseWithClaims,
		// but treat it defensively as an inactive token rather than an infra error.
		return &domain.IntrospectionResult{Active: false}, nil
	}

	return claimsToResult(claims), nil
}
