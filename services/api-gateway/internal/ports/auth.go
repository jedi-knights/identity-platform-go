package ports

// VerifiedClaims holds the identity facts extracted from a validated Bearer token.
// The fields mirror the subset of jwtutil.Claims used to build upstream-facing
// X-Auth-* headers. Adding fields here is a backwards-compatible extension point.
type VerifiedClaims struct {
	Subject string
	Scope   string
	Roles   []string
}

// TokenVerifier is the inbound port for validating Bearer tokens.
//
// Design: Strategy pattern — the concrete algorithm (HMAC HS256, RSA RS256 via JWKS,
// or any future scheme) is injected at container construction time so the JWT
// middleware never knows how tokens are signed or which key material is in use.
//
// Verify returns the verified identity claims on success. On failure it returns one
// of the sentinel errors from jwtutil (ErrTokenExpired, ErrTokenInvalid,
// ErrTokenMalformed); callers use errors.Is to distinguish failure modes.
type TokenVerifier interface {
	Verify(token string) (*VerifiedClaims, error)
}
