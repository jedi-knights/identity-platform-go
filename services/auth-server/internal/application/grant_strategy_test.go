package application_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// Ensure the mock returns domain.ErrTokenNotFound so TokenService.Introspect can
// distinguish "token was revoked" from genuine infrastructure errors.

// mockClientAuthenticator implements ports.ClientAuthenticator for testing.
type mockClientAuthenticator struct {
	clients map[string]*domain.Client
}

func newMockClientAuthenticator() *mockClientAuthenticator {
	return &mockClientAuthenticator{clients: make(map[string]*domain.Client)}
}

func (m *mockClientAuthenticator) Authenticate(_ context.Context, clientID, clientSecret string) (*domain.Client, error) {
	c, ok := m.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("not found: %s", clientID)
	}
	if c.Secret != clientSecret {
		return nil, fmt.Errorf("invalid credentials")
	}
	return c, nil
}

// mockTokenRepo implements domain.TokenRepository for testing.
type mockTokenRepo struct {
	tokens map[string]*domain.Token
}

func newMockTokenRepo() *mockTokenRepo {
	return &mockTokenRepo{tokens: make(map[string]*domain.Token)}
}

func (m *mockTokenRepo) Save(_ context.Context, t *domain.Token) error {
	m.tokens[t.Raw] = t
	return nil
}

func (m *mockTokenRepo) FindByRaw(_ context.Context, raw string) (*domain.Token, error) {
	t, ok := m.tokens[raw]
	if !ok {
		return nil, fmt.Errorf("%w", domain.ErrTokenNotFound)
	}
	return t, nil
}

func (m *mockTokenRepo) Delete(_ context.Context, raw string) error {
	delete(m.tokens, raw)
	return nil
}

// mockRefreshTokenRepo implements domain.RefreshTokenRepository for testing.
type mockRefreshTokenRepo struct {
	tokens map[string]*domain.RefreshToken
}

func newMockRefreshTokenRepo() *mockRefreshTokenRepo {
	return &mockRefreshTokenRepo{tokens: make(map[string]*domain.RefreshToken)}
}

func (m *mockRefreshTokenRepo) Save(_ context.Context, t *domain.RefreshToken) error {
	m.tokens[t.Raw] = t
	return nil
}

func (m *mockRefreshTokenRepo) FindByRaw(_ context.Context, raw string) (*domain.RefreshToken, error) {
	t, ok := m.tokens[raw]
	if !ok {
		return nil, domain.ErrRefreshTokenNotFound
	}
	return t, nil
}

func (m *mockRefreshTokenRepo) Delete(_ context.Context, raw string) error {
	if _, ok := m.tokens[raw]; !ok {
		return domain.ErrRefreshTokenNotFound
	}
	delete(m.tokens, raw)
	return nil
}

// mockTokenGen always returns a fixed token string.
type mockTokenGen struct{}

func (m *mockTokenGen) Generate(_ context.Context, _ *domain.Token) (string, error) {
	return "mock-token-123", nil
}

func newTestClient(id, secret string, scopes []string, grants []domain.GrantType) *domain.Client {
	return &domain.Client{
		ID:         id,
		Secret:     secret,
		Name:       "Test Client",
		Scopes:     scopes,
		GrantTypes: grants,
	}
}

// --- ClientCredentialsStrategy ---

func TestClientCredentialsStrategy_Handle_Success(t *testing.T) {
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	tokenGen := &mockTokenGen{}

	auth.clients["my-client"] = newTestClient(
		"my-client", "my-secret",
		[]string{"read"},
		[]domain.GrantType{domain.GrantTypeClientCredentials},
	)

	strategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour)

	resp, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:    domain.GrantTypeClientCredentials,
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		Scopes:       []string{"read"},
	})

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if resp.AccessToken != "mock-token-123" {
		t.Errorf("expected mock-token-123, got: %s", resp.AccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected Bearer token type, got: %s", resp.TokenType)
	}
}

func TestClientCredentialsStrategy_Handle_IssuesRefreshToken(t *testing.T) {
	// Characterization test: Handle must persist a refresh token in the repository.
	// Required before the issueRefreshToken extraction refactor (M3).
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	tokenGen := &mockTokenGen{}

	auth.clients["my-client"] = newTestClient(
		"my-client", "my-secret",
		[]string{"read"},
		[]domain.GrantType{domain.GrantTypeClientCredentials},
	)

	strategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour)

	resp, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:    domain.GrantTypeClientCredentials,
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		Scopes:       []string{"read"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.RefreshToken == "" {
		t.Fatal("expected non-empty RefreshToken in response")
	}
	if _, err := refreshTokenRepo.FindByRaw(context.Background(), resp.RefreshToken); err != nil {
		t.Errorf("refresh token not found in repo after Handle: %v", err)
	}
}

func TestClientCredentialsStrategy_Handle_WrongSecret(t *testing.T) {
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	tokenGen := &mockTokenGen{}

	auth.clients["my-client"] = newTestClient(
		"my-client", "correct-secret",
		[]string{"read"},
		[]domain.GrantType{domain.GrantTypeClientCredentials},
	)

	strategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour)

	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:    domain.GrantTypeClientCredentials,
		ClientID:     "my-client",
		ClientSecret: "wrong-secret",
	})

	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestClientCredentialsStrategy_Handle_ClientNotFound(t *testing.T) {
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	tokenGen := &mockTokenGen{}

	strategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour)

	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:    domain.GrantTypeClientCredentials,
		ClientID:     "nonexistent",
		ClientSecret: "secret",
	})

	if err == nil {
		t.Fatal("expected error for nonexistent client")
	}
}

func TestClientCredentialsStrategy_Handle_ScopeNotAllowed(t *testing.T) {
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	tokenGen := &mockTokenGen{}

	auth.clients["my-client"] = newTestClient(
		"my-client", "secret",
		[]string{"read"},
		[]domain.GrantType{domain.GrantTypeClientCredentials},
	)

	strategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour)

	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:    domain.GrantTypeClientCredentials,
		ClientID:     "my-client",
		ClientSecret: "secret",
		Scopes:       []string{"admin"},
	})

	if err == nil {
		t.Fatal("expected error for disallowed scope")
	}
}

// --- RefreshTokenStrategy ---

// seedRefreshToken creates and saves a refresh token for use in tests.
func seedRefreshToken(t *testing.T, repo *mockRefreshTokenRepo, raw, clientID, subject string, scopes []string, expiresIn time.Duration) {
	t.Helper()
	rt := &domain.RefreshToken{
		ID:        "rt-id-" + raw,
		Raw:       raw,
		ClientID:  clientID,
		Subject:   subject,
		Scopes:    scopes,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(expiresIn),
	}
	if err := repo.Save(context.Background(), rt); err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}
}

func newRefreshTokenStrategy(auth *mockClientAuthenticator, tokenRepo *mockTokenRepo, refreshRepo *mockRefreshTokenRepo) *application.RefreshTokenStrategy {
	return application.NewRefreshTokenStrategy(auth, tokenRepo, refreshRepo, &mockTokenGen{}, nil, time.Hour, 7*24*time.Hour)
}

func TestRefreshTokenStrategy_Handle_Success(t *testing.T) {
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshRepo := newMockRefreshTokenRepo()

	auth.clients["client1"] = newTestClient("client1", "secret", []string{"read"}, []domain.GrantType{domain.GrantTypeRefreshToken})
	seedRefreshToken(t, refreshRepo, "refresh-raw-1", "client1", "client1", []string{"read"}, 7*24*time.Hour)

	strategy := newRefreshTokenStrategy(auth, tokenRepo, refreshRepo)
	resp, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:    domain.GrantTypeRefreshToken,
		ClientID:     "client1",
		ClientSecret: "secret",
		RefreshToken: "refresh-raw-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected non-empty refresh token in response (rotation)")
	}
}

func TestRefreshTokenStrategy_Handle_RotatesRefreshToken(t *testing.T) {
	// Old refresh token must be deleted; a new one must be stored.
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshRepo := newMockRefreshTokenRepo()

	auth.clients["client1"] = newTestClient("client1", "secret", []string{"read"}, []domain.GrantType{domain.GrantTypeRefreshToken})
	seedRefreshToken(t, refreshRepo, "old-refresh", "client1", "client1", []string{"read"}, 7*24*time.Hour)

	strategy := newRefreshTokenStrategy(auth, tokenRepo, refreshRepo)
	resp, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:    domain.GrantTypeRefreshToken,
		ClientID:     "client1",
		ClientSecret: "secret",
		RefreshToken: "old-refresh",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Old token must be gone.
	if _, err := refreshRepo.FindByRaw(context.Background(), "old-refresh"); err == nil {
		t.Error("old refresh token should have been deleted after rotation")
	}
	// New token must be stored.
	if _, err := refreshRepo.FindByRaw(context.Background(), resp.RefreshToken); err != nil {
		t.Errorf("new refresh token not found in repo: %v", err)
	}
}

func TestRefreshTokenStrategy_Handle_InvalidClient(t *testing.T) {
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshRepo := newMockRefreshTokenRepo()
	// No client registered — authentication will fail.

	strategy := newRefreshTokenStrategy(auth, tokenRepo, refreshRepo)
	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:    domain.GrantTypeRefreshToken,
		ClientID:     "unknown",
		ClientSecret: "secret",
		RefreshToken: "any",
	})
	if err == nil {
		t.Fatal("expected error for unknown client")
	}
}

func TestRefreshTokenStrategy_Handle_RefreshTokenNotFound(t *testing.T) {
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshRepo := newMockRefreshTokenRepo()

	auth.clients["client1"] = newTestClient("client1", "secret", []string{"read"}, []domain.GrantType{domain.GrantTypeRefreshToken})
	// No refresh token seeded.

	strategy := newRefreshTokenStrategy(auth, tokenRepo, refreshRepo)
	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:    domain.GrantTypeRefreshToken,
		ClientID:     "client1",
		ClientSecret: "secret",
		RefreshToken: "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for missing refresh token")
	}
}

func TestRefreshTokenStrategy_Handle_WrongClientID(t *testing.T) {
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshRepo := newMockRefreshTokenRepo()

	auth.clients["client1"] = newTestClient("client1", "secret", []string{"read"}, []domain.GrantType{domain.GrantTypeRefreshToken})
	auth.clients["client2"] = newTestClient("client2", "secret2", []string{"read"}, []domain.GrantType{domain.GrantTypeRefreshToken})
	// Refresh token belongs to client1.
	seedRefreshToken(t, refreshRepo, "refresh-raw", "client1", "client1", []string{"read"}, 7*24*time.Hour)

	strategy := newRefreshTokenStrategy(auth, tokenRepo, refreshRepo)
	// client2 tries to use client1's token.
	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:    domain.GrantTypeRefreshToken,
		ClientID:     "client2",
		ClientSecret: "secret2",
		RefreshToken: "refresh-raw",
	})
	if err == nil {
		t.Fatal("expected error when refresh token belongs to a different client")
	}
}

func TestRefreshTokenStrategy_Handle_ExpiredRefreshToken(t *testing.T) {
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshRepo := newMockRefreshTokenRepo()

	auth.clients["client1"] = newTestClient("client1", "secret", []string{"read"}, []domain.GrantType{domain.GrantTypeRefreshToken})
	seedRefreshToken(t, refreshRepo, "expired-refresh", "client1", "client1", []string{"read"}, -time.Hour) // already expired

	strategy := newRefreshTokenStrategy(auth, tokenRepo, refreshRepo)
	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:    domain.GrantTypeRefreshToken,
		ClientID:     "client1",
		ClientSecret: "secret",
		RefreshToken: "expired-refresh",
	})
	if err == nil {
		t.Fatal("expected error for expired refresh token")
	}
}

// --- GrantStrategyRegistry ---

func TestGrantStrategyRegistry_Handle_UnsupportedGrant(t *testing.T) {
	registry := application.NewGrantStrategyRegistry()
	_, err := registry.Handle(context.Background(), domain.GrantRequest{
		GrantType: "unsupported_grant",
	})
	if err == nil {
		t.Fatal("expected error for unsupported grant type")
	}
}

func TestGrantStrategyRegistry_Handle_Routes(t *testing.T) {
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	tokenGen := &mockTokenGen{}

	auth.clients["c1"] = newTestClient(
		"c1", "secret",
		[]string{"read"},
		[]domain.GrantType{domain.GrantTypeClientCredentials},
	)

	ccStrategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour)
	registry := application.NewGrantStrategyRegistry(ccStrategy)

	resp, err := registry.Handle(context.Background(), domain.GrantRequest{
		GrantType:    domain.GrantTypeClientCredentials,
		ClientID:     "c1",
		ClientSecret: "secret",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Scope != "read" {
		t.Errorf("expected scope 'read' (client default), got %q", resp.Scope)
	}
}

func TestClientCredentialsStrategy_Supports(t *testing.T) {
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	tokenGen := &mockTokenGen{}

	ccStrategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour)

	if !ccStrategy.Supports(domain.GrantTypeClientCredentials) {
		t.Error("expected client_credentials to be supported")
	}
	if ccStrategy.Supports(domain.GrantTypeAuthorizationCode) {
		t.Error("expected authorization_code not to be supported by cc strategy")
	}
}

func TestAuthorizationCodeStrategy_Handle_ReturnsNotImplemented(t *testing.T) {
	// Arrange
	strategy := application.NewAuthorizationCodeStrategy(nil, nil, nil, time.Hour, nil)

	// Act
	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType: domain.GrantTypeAuthorizationCode,
	})

	// Assert — stub always returns ErrUnsupportedGrantType; credential fields no longer exist
	if err == nil {
		t.Fatal("expected stub error, got nil")
	}
	if !errors.Is(err, application.ErrUnsupportedGrantType) {
		t.Errorf("error = %v, want ErrUnsupportedGrantType", err)
	}
}
