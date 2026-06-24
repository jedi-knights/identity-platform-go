package application

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jedi-knights/go-platform/jwtutil"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// IDTokenIssuance is the request body NewIDTokenGenerator.Generate consumes.
// The caller (AuthorizationCodeStrategy) is responsible for populating the
// fields appropriate to the granted scopes — the issuer copies what it
// receives without re-checking scope membership. Compositional split.
type IDTokenIssuance struct {
	Subject  string
	Audience string // client_id of the relying party (OIDC §2)
	Nonce    string
	AtHash   string
	AuthTime time.Time
	AMR      []string

	// Profile / email claims. Empty fields are omitted from the issued ID
	// token via the omitempty tag on IDClaims.
	Email         string
	EmailVerified *bool
	Name          string
	UpdatedAt     time.Time

	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IDTokenGenerator issues OIDC ID tokens signed with RS256 against the same
// KeySet auth-server's access tokens use. The issuer URL is taken from
// AUTH_OIDC_ISSUER (ADR-0010) and copied into the iss claim verbatim — the
// caller is responsible for ensuring the configured value matches what the
// JWKS metadata (ADR-0012) advertises.
type IDTokenGenerator struct {
	keys   *domain.KeySet
	issuer string
}

// NewIDTokenGenerator wires the generator to a KeySet and the configured
// OIDC issuer URL. Nil keys or empty issuer is a programmer error — the
// constructor panics rather than producing tokens with empty iss claims.
func NewIDTokenGenerator(keys *domain.KeySet, issuer string) *IDTokenGenerator {
	if keys == nil {
		panic("NewIDTokenGenerator: keys must not be nil")
	}
	if issuer == "" {
		panic("NewIDTokenGenerator: issuer must not be empty")
	}
	return &IDTokenGenerator{keys: keys, issuer: issuer}
}

// Generate builds an IDClaims value from req and signs it with the active
// signing key. The kid header on the issued token matches Current() — the
// same key the access-token generator is using right now, so a verifier
// that successfully resolved the access-token kid will also resolve this one.
func (g *IDTokenGenerator) Generate(_ context.Context, req IDTokenIssuance) (string, error) {
	current := g.keys.Current()
	if current == nil {
		return "", fmt.Errorf("issuing ID token: KeySet has no current key")
	}
	claims := &jwtutil.IDClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.issuer,
			Subject:   req.Subject,
			Audience:  jwt.ClaimStrings{req.Audience},
			IssuedAt:  jwt.NewNumericDate(req.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(req.ExpiresAt),
		},
		Nonce:         req.Nonce,
		AtHash:        req.AtHash,
		AMR:           append([]string(nil), req.AMR...),
		Email:         req.Email,
		EmailVerified: req.EmailVerified,
		Name:          req.Name,
	}
	if !req.AuthTime.IsZero() {
		claims.AuthTime = req.AuthTime.Unix()
	}
	if !req.UpdatedAt.IsZero() {
		claims.UpdatedAt = req.UpdatedAt.Unix()
	}
	return jwtutil.SignIDToken(claims, current.Private, current.KID)
}
