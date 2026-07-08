package application

import (
	"context"
	"fmt"
	"slices"

	"github.com/golang-jwt/jwt/v5"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// ClientAssertionValidator verifies RFC 7523 §3 JWT-bearer client
// assertions (ADR-0023). Deliberately not a jwtutil.ParseRS256 caller —
// that function hard-enforces the platform's own RFC 9068 "at+jwt" JOSE
// header, which a third-party client assertion never carries.
//
// Sits in the application layer, not an adapter — it depends only on
// port interfaces (ClientLookup, ClientJWKSFetcher) and a domain
// repository, exactly like every GrantStrategy in this package.
type ClientAssertionValidator struct {
	clientLookup ports.ClientLookup
	jwksFetcher  ports.ClientJWKSFetcher
	replayRepo   domain.ClientAssertionReplayRepository
	// audience is this server's token-endpoint issuer identifier — the
	// value RFC 7523 §3 requires a client assertion's aud claim to
	// contain.
	audience string
}

// NewClientAssertionValidator constructs a validator. audience is
// typically the same value as JWTConfig.Issuer.
func NewClientAssertionValidator(
	clientLookup ports.ClientLookup,
	jwksFetcher ports.ClientJWKSFetcher,
	replayRepo domain.ClientAssertionReplayRepository,
	audience string,
) *ClientAssertionValidator {
	return &ClientAssertionValidator{
		clientLookup: clientLookup,
		jwksFetcher:  jwksFetcher,
		replayRepo:   replayRepo,
		audience:     audience,
	}
}

// Authenticate resolves clientID via ClientLookup, verifies assertion
// against the client's registered JWKS, validates its RFC 7523 §3 claims,
// and records its jti as consumed. Returns the same *domain.Client shape
// ports.ClientAuthenticator.Authenticate would for secret-based auth.
func (v *ClientAssertionValidator) Authenticate(ctx context.Context, clientID, assertion string) (*domain.Client, error) {
	client, err := v.clientLookup.Lookup(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client.JWKSURI == "" {
		return nil, apperrors.New(apperrors.ErrCodeUnauthorized, "client is not registered for JWT-bearer authentication")
	}
	claims, err := v.parse(ctx, assertion, client.JWKSURI)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeUnauthorized, "client assertion invalid", err)
	}
	if err := v.validateClaims(claims, clientID); err != nil {
		return nil, err
	}
	if err := v.replayRepo.MarkUsed(ctx, claims.ID, claims.ExpiresAt.Time); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeUnauthorized, "client assertion rejected", err)
	}
	return client, nil
}

// parse verifies the assertion's signature against jwksURI and returns
// its registered claims. RS256 is the only accepted algorithm — RFC 8725
// §3.1's algorithm-confusion defense, same stance ADR-0008 already takes
// for this platform's own access tokens.
func (v *ClientAssertionValidator) parse(ctx context.Context, assertion, jwksURI string) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(assertion, claims, v.keyfunc(ctx, jwksURI), jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("client assertion failed validation")
	}
	return claims, nil
}

// keyfunc resolves the verification key via jwksFetcher, keyed by the
// assertion's kid header.
func (v *ClientAssertionValidator) keyfunc(ctx context.Context, jwksURI string) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("client assertion missing kid header")
		}
		pub, err := v.jwksFetcher.FetchKey(ctx, jwksURI, kid)
		if err != nil {
			return nil, fmt.Errorf("resolving key for kid %q: %w", kid, err)
		}
		return pub, nil
	}
}

// validateClaims enforces RFC 7523 §3's claim requirements beyond
// signature verification: iss and sub must both equal clientID (checked
// after — not instead of — signature verification, so this corroborates
// a cryptographically proven claim rather than trusting an unverified
// one), aud must contain this server's issuer, and exp/jti must be
// present. jwt.ParseWithClaims already rejects an expired exp when
// present; this only adds the "must be present at all" requirement.
func (v *ClientAssertionValidator) validateClaims(claims *jwt.RegisteredClaims, clientID string) error {
	if claims.Issuer != clientID || claims.Subject != clientID {
		return apperrors.New(apperrors.ErrCodeUnauthorized, "client assertion iss/sub must equal client_id")
	}
	if !slices.Contains(claims.Audience, v.audience) {
		return apperrors.New(apperrors.ErrCodeUnauthorized, "client assertion aud does not match token endpoint")
	}
	if claims.ExpiresAt == nil {
		return apperrors.New(apperrors.ErrCodeUnauthorized, "client assertion missing exp claim")
	}
	if claims.ID == "" {
		return apperrors.New(apperrors.ErrCodeUnauthorized, "client assertion missing jti claim")
	}
	return nil
}
