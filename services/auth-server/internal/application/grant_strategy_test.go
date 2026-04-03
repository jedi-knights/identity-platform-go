//go:build unit

package application_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// --- Manual mock for ClientRepository ---
type mockClientRepo struct {
	clients map[string]*domain.Client
}

func newMockClientRepo() *mockClientRepo {
	return &mockClientRepo{clients: make(map[string]*domain.Client)}
}

func (m *mockClientRepo) FindByID(id string) (*domain.Client, error) {
	c, ok := m.clients[id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", id)
	}
	return c, nil
}

func (m *mockClientRepo) Save(c *domain.Client) error {
	m.clients[c.ID] = c
	return nil
}

// --- Manual mock for TokenRepository ---
type mockTokenRepo struct {
	tokens map[string]*domain.Token
}

func newMockTokenRepo() *mockTokenRepo {
	return &mockTokenRepo{tokens: make(map[string]*domain.Token)}
}

func (m *mockTokenRepo) Save(t *domain.Token) error {
	m.tokens[t.Raw] = t
	return nil
}

func (m *mockTokenRepo) FindByRaw(raw string) (*domain.Token, error) {
	t, ok := m.tokens[raw]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return t, nil
}

func (m *mockTokenRepo) Delete(raw string) error {
	delete(m.tokens, raw)
	return nil
}

// --- Manual mock for TokenGenerator ---
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

func TestClientCredentialsStrategy_Handle_Success(t *testing.T) {
	clientRepo := newMockClientRepo()
	tokenRepo := newMockTokenRepo()
	tokenGen := &mockTokenGen{}

	clientRepo.clients["my-client"] = newTestClient(
		"my-client", "my-secret",
		[]string{"read"},
		[]domain.GrantType{domain.GrantTypeClientCredentials},
	)

	strategy := application.NewClientCredentialsStrategy(clientRepo, tokenRepo, tokenGen, time.Hour)

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

func TestClientCredentialsStrategy_Handle_WrongSecret(t *testing.T) {
	clientRepo := newMockClientRepo()
	tokenRepo := newMockTokenRepo()
	tokenGen := &mockTokenGen{}

	clientRepo.clients["my-client"] = newTestClient(
		"my-client", "correct-secret",
		[]string{"read"},
		[]domain.GrantType{domain.GrantTypeClientCredentials},
	)

	strategy := application.NewClientCredentialsStrategy(clientRepo, tokenRepo, tokenGen, time.Hour)

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
	clientRepo := newMockClientRepo()
	tokenRepo := newMockTokenRepo()
	tokenGen := &mockTokenGen{}

	strategy := application.NewClientCredentialsStrategy(clientRepo, tokenRepo, tokenGen, time.Hour)

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
	clientRepo := newMockClientRepo()
	tokenRepo := newMockTokenRepo()
	tokenGen := &mockTokenGen{}

	clientRepo.clients["my-client"] = newTestClient(
		"my-client", "secret",
		[]string{"read"},
		[]domain.GrantType{domain.GrantTypeClientCredentials},
	)

	strategy := application.NewClientCredentialsStrategy(clientRepo, tokenRepo, tokenGen, time.Hour)

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
	clientRepo := newMockClientRepo()
	tokenRepo := newMockTokenRepo()
	tokenGen := &mockTokenGen{}

	clientRepo.clients["c1"] = newTestClient(
		"c1", "secret",
		[]string{"read"},
		[]domain.GrantType{domain.GrantTypeClientCredentials},
	)

	ccStrategy := application.NewClientCredentialsStrategy(clientRepo, tokenRepo, tokenGen, time.Hour)
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
}

func TestClientCredentialsStrategy_Supports(t *testing.T) {
	clientRepo := newMockClientRepo()
	tokenRepo := newMockTokenRepo()
	tokenGen := &mockTokenGen{}

	ccStrategy := application.NewClientCredentialsStrategy(clientRepo, tokenRepo, tokenGen, time.Hour)

	if !ccStrategy.Supports(domain.GrantTypeClientCredentials) {
		t.Error("expected client_credentials to be supported")
	}
	if ccStrategy.Supports(domain.GrantTypeAuthorizationCode) {
		t.Error("expected authorization_code not to be supported by cc strategy")
	}
}
