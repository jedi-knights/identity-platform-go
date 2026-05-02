// Package hs256 provides a ports.TokenVerifier that validates HMAC-SHA256 (HS256)
// signed JWT Bearer tokens using the shared jwtutil library.
package hs256

import (
	"github.com/ocrosby/identity-platform-go/libs/jwtutil"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// Compile-time check: Verifier must satisfy ports.TokenVerifier.
var _ ports.TokenVerifier = (*Verifier)(nil)

// Verifier validates HS256 Bearer tokens.
//
// Design: Adapter pattern — Verifier adapts the shared jwtutil library to the
// gateway's ports.TokenVerifier interface, decoupling the middleware from the
// signing algorithm and key material.
type Verifier struct {
	signingKey []byte
}

// NewVerifier creates an HS256 Verifier using the given HMAC-SHA256 secret.
func NewVerifier(signingKey []byte) *Verifier {
	return &Verifier{signingKey: signingKey}
}

// Verify parses and validates the raw JWT string, returning the identity claims
// on success. It delegates signature verification and expiry checking to jwtutil.Parse.
// Returns jwtutil sentinel errors (ErrTokenExpired, ErrTokenInvalid, ErrTokenMalformed)
// so callers can use errors.Is without importing the jwt library.
func (v *Verifier) Verify(token string) (*ports.VerifiedClaims, error) {
	claims, err := jwtutil.Parse(token, v.signingKey)
	if err != nil {
		return nil, err
	}
	return &ports.VerifiedClaims{
		Subject: claims.Subject,
		Scope:   claims.Scope,
		Roles:   claims.Roles,
	}, nil
}
