package application_test

import (
	"context"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// TestClientCredentialsStrategy_Handle_AuthenticatesViaClientAssertion
// confirms the wiring, not the assertion-verification logic itself
// (covered exhaustively by client_assertion_validator_test.go): a
// ClientCredentialsStrategy configured with a ClientAssertionValidator
// (ADR-0023) issues a token for a request that presents a valid
// client_assertion instead of a client_secret.
func TestClientCredentialsStrategy_Handle_AuthenticatesViaClientAssertion(t *testing.T) {
	// Arrange
	priv := newAssertionTestRSAKey(t)
	lookup := newFakeClientLookup()
	lookup.clients["jwt-client"] = &domain.Client{
		ID:         "jwt-client",
		JWKSURI:    "https://client.example.com/jwks.json",
		Scopes:     []string{"read"},
		GrantTypes: []domain.GrantType{domain.GrantTypeClientCredentials},
	}
	fetcher := newFakeJWKSFetcher()
	fetcher.keys["kid-1"] = &priv.PublicKey
	assertionAuth := application.NewClientAssertionValidator(lookup, fetcher, newFakeReplayRepo(), testTokenEndpointIssuer)

	auth := newMockClientAuthenticator() // secret-based path unused by this test
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	strategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, &mockTokenGen{}, nil, time.Hour, 7*24*time.Hour, assertionAuth)
	assertion := signAssertion(t, priv, "kid-1", validAssertionClaims("jwt-client"))

	// Act
	resp, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:           domain.GrantTypeClientCredentials,
		ClientID:            "jwt-client",
		ClientAssertion:     assertion,
		ClientAssertionType: domain.ClientAssertionTypeJWTBearer,
		Scopes:              []string{"read"},
	})

	// Assert
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.AccessToken != "mock-token-123" {
		t.Errorf("AccessToken = %q", resp.AccessToken)
	}
}

// TestClientCredentialsStrategy_Handle_AssertionPresentButNotConfigured
// confirms a request carrying a client_assertion is rejected — not
// silently treated as a secret-based request — when the strategy has no
// ClientAssertionValidator wired.
func TestClientCredentialsStrategy_Handle_AssertionPresentButNotConfigured(t *testing.T) {
	// Arrange
	auth := newMockClientAuthenticator()
	auth.clients["jwt-client"] = newTestClient("jwt-client", "some-secret", []string{"read"}, []domain.GrantType{domain.GrantTypeClientCredentials})
	strategy := application.NewClientCredentialsStrategy(auth, newMockTokenRepo(), newMockRefreshTokenRepo(), &mockTokenGen{}, nil, time.Hour, 7*24*time.Hour, nil)

	// Act
	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:           domain.GrantTypeClientCredentials,
		ClientID:            "jwt-client",
		ClientAssertion:     "header.payload.signature",
		ClientAssertionType: domain.ClientAssertionTypeJWTBearer,
		Scopes:              []string{"read"},
	})

	// Assert
	if !apperrors.IsUnauthorized(err) {
		t.Errorf("err = %v, want ErrCodeUnauthorized", err)
	}
}
