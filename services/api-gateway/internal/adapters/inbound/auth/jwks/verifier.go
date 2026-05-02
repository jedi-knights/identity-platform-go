// Package jwks provides a ports.TokenVerifier that validates RS256 JWT Bearer
// tokens using a remote JWKS endpoint with automatic background key refresh.
//
// Design: Adapter pattern — Verifier adapts github.com/MicahParks/keyfunc/v3
// to the gateway's ports.TokenVerifier interface. The keyfunc library handles
// HTTP fetching, JSON parsing, and background refresh of the JWKS key set.
// The context passed to New governs the refresh goroutine lifetime.
package jwks

import (
	"context"
	"errors"
	"fmt"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"

	"github.com/ocrosby/identity-platform-go/libs/jwtutil"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// Compile-time check: Verifier must satisfy ports.TokenVerifier.
var _ ports.TokenVerifier = (*Verifier)(nil)

// Verifier validates RS256 JWT Bearer tokens using a JWKS endpoint.
//
// Key refresh runs in the background for the lifetime of the context passed to
// New. When the context is cancelled (e.g. on gateway shutdown), the refresh
// goroutine exits cleanly.
//
// Issuer and Audience validation are applied when the corresponding fields are
// non-empty; omit them to accept tokens from any issuer or audience.
type Verifier struct {
	kf       keyfunc.Keyfunc
	issuer   string
	audience string
}

// New creates a Verifier that fetches and caches the JWKS from cfg.JWKSUrl.
// ctx controls the background key-refresh goroutine — cancel it on shutdown.
func New(ctx context.Context, cfg config.AuthConfig) (*Verifier, error) {
	if cfg.JWKSUrl == "" {
		return nil, fmt.Errorf("jwks: jwks_url must be set when auth.type is \"jwks\"")
	}
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{cfg.JWKSUrl})
	if err != nil {
		return nil, fmt.Errorf("jwks: initialising keyfunc from %q: %w", cfg.JWKSUrl, err)
	}
	return &Verifier{kf: kf, issuer: cfg.Issuer, audience: cfg.Audience}, nil
}

// Verify parses and validates the raw JWT string.
// Returns the verified identity claims on success, or a jwtutil sentinel error
// (ErrTokenExpired, ErrTokenInvalid, ErrTokenMalformed) on failure.
func (v *Verifier) Verify(raw string) (*ports.VerifiedClaims, error) {
	token, err := jwt.ParseWithClaims(raw, &jwtutil.Claims{}, v.kf.Keyfunc, v.parserOptions()...)
	if err != nil {
		return nil, mapJWTError(err)
	}
	claims, ok := token.Claims.(*jwtutil.Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("%w", jwtutil.ErrTokenInvalid)
	}
	return &ports.VerifiedClaims{
		Subject: claims.Subject,
		Scope:   claims.Scope,
		Roles:   claims.Roles,
	}, nil
}

// parserOptions builds the jwt.ParserOption slice based on configured constraints.
func (v *Verifier) parserOptions() []jwt.ParserOption {
	opts := []jwt.ParserOption{jwt.WithIssuedAt()}
	if v.issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.issuer))
	}
	if v.audience != "" {
		opts = append(opts, jwt.WithAudience(v.audience))
	}
	return opts
}

// mapJWTError converts jwt library errors to jwtutil sentinel errors so callers
// do not need to import the jwt library to inspect failure reasons.
func mapJWTError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return fmt.Errorf("%w", jwtutil.ErrTokenExpired)
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return fmt.Errorf("%w", jwtutil.ErrTokenInvalid)
	case errors.Is(err, jwt.ErrTokenMalformed):
		return fmt.Errorf("%w", jwtutil.ErrTokenMalformed)
	default:
		return fmt.Errorf("%w", jwtutil.ErrTokenInvalid)
	}
}
