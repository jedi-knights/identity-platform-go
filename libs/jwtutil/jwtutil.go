// Package jwtutil provides shared JWT signing and parsing for the identity platform.
//
// It encapsulates the HMAC key-function boilerplate and the canonical Claims type
// so that all services use a single definition. Callers decide how to handle errors
// returned by Parse — RFC 7662 §2.2 compliance (returning {active:false} instead of
// an error) is the responsibility of the caller, not this package.
package jwtutil

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Sentinel errors returned by Parse. Callers use errors.Is to distinguish failure
// modes without importing the jwt library directly, keeping the jwt dependency
// contained to this package.
var (
	// ErrTokenExpired is returned when the token's expiry time has passed.
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenInvalid is returned for signature failures, algorithm mismatches,
	// or any other validity failure not covered by a more specific sentinel.
	ErrTokenInvalid = errors.New("token invalid")
	// ErrTokenMalformed is returned when the raw string is not a well-formed JWT.
	ErrTokenMalformed = errors.New("token malformed")
)

// Claims is the canonical JWT claims type for identity-platform access tokens.
// Scope is a space-delimited string per RFC 9068 §2.2.3.1.
// Roles lists the RBAC roles assigned to the subject at token issuance.
// Permissions lists the resolved permissions (format: "resource:action") granted
// by the subject's roles at token issuance. Resource services use this claim for
// local authorization evaluation without an outbound policy service call.
// Both fields are omitempty — tokens issued without RBAC context omit them.
type Claims struct {
	jwt.RegisteredClaims
	ClientID    string   `json:"client_id"`
	Scope       string   `json:"scope"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// ClaimsConfig holds all inputs for NewClaims. Using a config struct instead of
// positional parameters prevents argument transposition at call sites — a risk
// with nine string/time parameters that format identically in error messages.
type ClaimsConfig struct {
	Issuer      string
	Subject     string
	TokenID     string
	ClientID    string
	Scope       string
	Roles       []string
	Permissions []string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// NewClaims constructs a Claims value from cfg, avoiding direct dependency on
// the jwt package in callers that only sign tokens.
// Roles and Permissions are defensively copied — callers may safely mutate
// their slices after calling NewClaims without affecting the returned Claims.
// Nil slices in cfg produce nil fields, which are omitted from the JWT (omitempty).
func NewClaims(cfg ClaimsConfig) *Claims {
	return &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			Subject:   cfg.Subject,
			ID:        cfg.TokenID,
			IssuedAt:  jwt.NewNumericDate(cfg.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(cfg.ExpiresAt),
		},
		ClientID:    cfg.ClientID,
		Scope:       cfg.Scope,
		Roles:       append([]string(nil), cfg.Roles...),
		Permissions: append([]string(nil), cfg.Permissions...),
	}
}

// Sign creates and signs a JWT using HMAC-SHA256.
// Returns an error if claims is nil or signingKey is empty — both produce
// either a panic or a cryptographically unsafe token in the underlying library.
func Sign(claims *Claims, signingKey []byte) (string, error) {
	if claims == nil {
		return "", fmt.Errorf("signing token: claims must not be nil")
	}
	if len(signingKey) == 0 {
		return "", fmt.Errorf("signing token: signing key must not be empty")
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, err := t.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}
	return raw, nil
}

// Parse parses and validates a raw JWT string signed with HMAC-SHA256.
// Returns a sentinel error (ErrTokenExpired, ErrTokenInvalid, ErrTokenMalformed)
// for specific failure modes so callers can distinguish them via errors.Is without
// importing the jwt library. Any error means the token is not valid for use.
// Callers that need RFC 7662 {active:false} semantics should treat any error as inactive.
func Parse(raw string, signingKey []byte) (*Claims, error) {
	if len(signingKey) == 0 {
		return nil, fmt.Errorf("parsing token: %w", ErrTokenInvalid)
	}
	token, err := jwt.ParseWithClaims(raw, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return signingKey, nil
	})
	if err != nil {
		return nil, mapJWTError(err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("parsing token: %w", ErrTokenInvalid)
	}

	return claims, nil
}

// mapJWTError converts jwt library errors to package sentinel errors so callers
// do not need to import the jwt library to inspect failure reasons.
func mapJWTError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return fmt.Errorf("parsing token: %w", ErrTokenExpired)
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return fmt.Errorf("parsing token: %w", ErrTokenInvalid)
	case errors.Is(err, jwt.ErrTokenMalformed):
		return fmt.Errorf("parsing token: %w", ErrTokenMalformed)
	default:
		return fmt.Errorf("parsing token: %w", ErrTokenInvalid)
	}
}
