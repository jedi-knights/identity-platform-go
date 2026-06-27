package application

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/jedi-knights/go-platform/jwtutil"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// RS256TokenGenerator issues access tokens signed with RSASSA-PKCS1-v1_5 SHA-256
// (RFC 7518 §3.3). Every token carries the active key's KID in the JOSE header
// so verifiers can look up the public key via JWKS (ADR-0008).
//
// The KeySet is shared with RS256TokenValidator — both observe the same set
// of live keys, so a key promoted from "next" to "current" is immediately
// available to both signing and (self-)verification without a wiring change.
type RS256TokenGenerator struct {
	keys     *domain.KeySet
	issuer   string
	audience []string // RFC 9068 §2.2: resource server identifiers; empty = no aud claim
}

// NewRS256TokenGenerator wires the generator to a KeySet. A nil keyset is a
// programmer error — the constructor panics rather than deferring the failure
// to the first token issuance, where it would surface as a confusing nil-deref
// inside the HTTP handler.
func NewRS256TokenGenerator(keys *domain.KeySet, issuer string, audience []string) *RS256TokenGenerator {
	if keys == nil {
		panic("NewRS256TokenGenerator: keys must not be nil")
	}
	return &RS256TokenGenerator{
		keys:     keys,
		issuer:   issuer,
		audience: append([]string(nil), audience...),
	}
}

// Generate signs the domain Token as an RS256 JWT using the current signing
// key. The resulting JWT carries typ:"at+jwt" (RFC 9068 §2.1) and kid (RFC 7517
// §4.5) in the JOSE header.
func (g *RS256TokenGenerator) Generate(_ context.Context, token *domain.Token) (string, error) {
	claims := jwtutil.NewClaims(jwtutil.ClaimsConfig{
		Issuer:      g.issuer,
		Subject:     token.Subject,
		TokenID:     token.ID,
		ClientID:    token.ClientID,
		Scope:       strings.Join(token.Scopes, " "),
		Audience:    g.audience,
		Roles:       token.Roles,
		Permissions: token.Permissions,
		ActorType:   string(token.ActorType),
		AgentID:     token.AgentID,
		IssuedAt:    token.IssuedAt,
		ExpiresAt:   token.ExpiresAt,
	})
	current := g.keys.Current()
	return jwtutil.SignRS256(claims, current.Private, current.KID)
}

// RS256TokenValidator verifies RS256-signed access tokens against the same
// KeySet the generator signs with. Auth-server uses this for its own
// /oauth/introspect handler; downstream resource servers go through a JWKS
// HTTP fetcher (Task #11 / #12) rather than holding the KeySet directly.
type RS256TokenValidator struct {
	keys      *domain.KeySet
	tokenRepo domain.TokenRepository
	issuer    string // when non-empty, tokens must carry this iss claim (RFC 8725 §3.8)
}

// NewRS256TokenValidator wires the validator to a KeySet. issuer may be empty —
// when set, tokens whose iss claim does not match are rejected.
func NewRS256TokenValidator(keys *domain.KeySet, tokenRepo domain.TokenRepository, issuer string) *RS256TokenValidator {
	if keys == nil {
		panic("NewRS256TokenValidator: keys must not be nil")
	}
	return &RS256TokenValidator{keys: keys, tokenRepo: tokenRepo, issuer: issuer}
}

// Validate parses raw as an RS256 JWT and returns the resulting domain.Token.
// Every error from jwtutil is a token-validation failure (expired, bad
// signature, unknown kid, malformed, wrong typ), not infrastructure error;
// callers should treat the error as {active:false} per RFC 7662 §2.2.
func (v *RS256TokenValidator) Validate(ctx context.Context, raw string) (*domain.Token, error) {
	keySource := func(_ context.Context, kid string) (*rsa.PublicKey, error) {
		return v.keys.KeyByID(kid)
	}
	claims, err := jwtutil.ParseRS256(ctx, raw, keySource)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if v.issuer != "" && claims.Issuer != v.issuer {
		// Constant-issuer mismatch — return ErrTokenInvalid-shaped error so
		// the introspection path maps to {active:false}.
		return nil, fmt.Errorf("invalid token: %w (iss %q != %q)", jwtutil.ErrTokenInvalid, claims.Issuer, v.issuer)
	}
	return &domain.Token{
		ID:        claims.ID,
		ClientID:  claims.ClientID,
		Subject:   claims.Subject,
		Issuer:    claims.Issuer,
		Audience:  []string(claims.Audience),
		Scopes:    strings.Fields(claims.Scope),
		ActorType: domain.ActorType(claims.ActorType),
		AgentID:   claims.AgentID,
		ExpiresAt: claims.ExpiresAt.Time,
		IssuedAt:  claims.IssuedAt.Time,
		TokenType: domain.TokenTypeBearer,
		Raw:       raw,
	}, nil
}
