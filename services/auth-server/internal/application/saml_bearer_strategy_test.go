package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

const samlTokenEndpoint = "https://as.example.com/oauth/token"

// samlBearerFixtures stamps a complete strategy + repos + client for the
// happy path; individual tests mutate req/client before calling Handle.
type samlBearerFixtures struct {
	strategy         *application.SAMLBearerStrategy
	clientAuth       *mockClientAuthenticator
	tokenRepo        *mockTokenRepo
	refreshTokenRepo *mockRefreshTokenRepo
	certPEM          string
	req              domain.GrantRequest
}

func newSAMLBearerFixtures(t *testing.T) *samlBearerFixtures {
	t.Helper()
	ks, certPEM := generateTestIssuer(t)

	clientAuth := newMockClientAuthenticator()
	client := newTestClient("saml-client", "secret-123", []string{"read", "write"}, []domain.GrantType{domain.GrantTypeSAML2Bearer})
	client.TrustedIssuerCert = certPEM
	clientAuth.clients["saml-client"] = client

	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	strategy := application.NewSAMLBearerStrategy(
		clientAuth, tokenRepo, refreshTokenRepo, &mockTokenGen{},
		application.NewSAMLBearerValidator(), samlTokenEndpoint, time.Hour,
	)

	opts := defaultAssertionOpts()
	opts.audience = samlTokenEndpoint
	opts.recipient = samlTokenEndpoint
	xmlBytes := signTestAssertion(t, ks, opts)

	return &samlBearerFixtures{
		strategy:         strategy,
		clientAuth:       clientAuth,
		tokenRepo:        tokenRepo,
		refreshTokenRepo: refreshTokenRepo,
		certPEM:          certPEM,
		req: domain.GrantRequest{
			GrantType:     domain.GrantTypeSAML2Bearer,
			ClientID:      "saml-client",
			ClientSecret:  "secret-123",
			Scopes:        []string{"read"},
			SAMLAssertion: string(xmlBytes),
		},
	}
}

func TestSAMLBearerStrategy_Handle_HappyPath_ReturnsAccessTokenNoRefresh(t *testing.T) {
	// Arrange
	f := newSAMLBearerFixtures(t)

	// Act
	resp, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("AccessToken is empty")
	}
	if resp.RefreshToken != "" {
		t.Error("expected no refresh token for the saml2-bearer grant")
	}
	if resp.Subject != "saml-user-1" {
		t.Errorf("Subject = %q, want %q", resp.Subject, "saml-user-1")
	}
}

func TestSAMLBearerStrategy_Handle_HappyPath_SavesTokenAsUserActor(t *testing.T) {
	// Arrange
	f := newSAMLBearerFixtures(t)

	// Act
	resp, err := f.strategy.Handle(context.Background(), f.req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	// Assert
	saved, ok := f.tokenRepo.tokens[resp.AccessToken]
	if !ok {
		t.Fatal("access token was not saved")
	}
	if saved.ActorType != domain.ActorTypeUser {
		t.Errorf("saved.ActorType = %q, want %q", saved.ActorType, domain.ActorTypeUser)
	}
	if saved.Subject != "saml-user-1" {
		t.Errorf("saved.Subject = %q, want %q", saved.Subject, "saml-user-1")
	}
}

func TestSAMLBearerStrategy_Handle_MissingAssertion_ReturnsInvalidRequest(t *testing.T) {
	// Arrange
	f := newSAMLBearerFixtures(t)
	f.req.SAMLAssertion = ""

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if !errors.Is(err, application.ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest, got: %v", err)
	}
}

func TestSAMLBearerStrategy_Handle_ClientWithoutGrantType_ReturnsUnauthorizedClient(t *testing.T) {
	// Arrange
	f := newSAMLBearerFixtures(t)
	f.clientAuth.clients["saml-client"].GrantTypes = []domain.GrantType{domain.GrantTypeClientCredentials}

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if !errors.Is(err, application.ErrUnauthorizedClient) {
		t.Errorf("expected ErrUnauthorizedClient, got: %v", err)
	}
}

func TestSAMLBearerStrategy_Handle_ClientWithNoTrustedIssuerCert_ReturnsInvalidGrant(t *testing.T) {
	// Arrange
	f := newSAMLBearerFixtures(t)
	f.clientAuth.clients["saml-client"].TrustedIssuerCert = ""

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if !errors.Is(err, application.ErrInvalidGrant) {
		t.Errorf("expected ErrInvalidGrant, got: %v", err)
	}
}

func TestSAMLBearerStrategy_Handle_InvalidAssertion_ReturnsInvalidGrant(t *testing.T) {
	// Arrange
	f := newSAMLBearerFixtures(t)
	f.req.SAMLAssertion = "not a valid assertion"

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if !errors.Is(err, application.ErrInvalidGrant) {
		t.Errorf("expected ErrInvalidGrant, got: %v", err)
	}
}

func TestSAMLBearerStrategy_Handle_ScopeNotAllowed_ReturnsForbidden(t *testing.T) {
	// Arrange
	f := newSAMLBearerFixtures(t)
	f.req.Scopes = []string{"admin"}

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if err == nil {
		t.Fatal("expected an error for a disallowed scope")
	}
}

func TestSAMLBearerStrategy_Supports(t *testing.T) {
	f := newSAMLBearerFixtures(t)
	if !f.strategy.Supports(domain.GrantTypeSAML2Bearer) {
		t.Error("expected Supports(GrantTypeSAML2Bearer) = true")
	}
	if f.strategy.Supports(domain.GrantTypeClientCredentials) {
		t.Error("expected Supports(GrantTypeClientCredentials) = false")
	}
}
