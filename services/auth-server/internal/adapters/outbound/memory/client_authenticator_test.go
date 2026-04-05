package memory_test

import (
	"context"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func testClient() *domain.Client {
	return &domain.Client{
		ID:         "client-1",
		Secret:     "correct-secret",
		Name:       "Test Client",
		Scopes:     []string{"read", "write"},
		GrantTypes: []domain.GrantType{domain.GrantTypeClientCredentials},
	}
}

func TestClientAuthenticator_Authenticate_Success(t *testing.T) {
	repo := memory.NewClientRepository([]*domain.Client{testClient()})
	auth := memory.NewClientAuthenticator(repo)

	client, err := auth.Authenticate(context.Background(), "client-1", "correct-secret")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if client.ID != "client-1" {
		t.Errorf("ID: got %q, want %q", client.ID, "client-1")
	}
	if len(client.Scopes) != 2 {
		t.Errorf("Scopes: got %d, want 2", len(client.Scopes))
	}
}

func TestClientAuthenticator_Authenticate_WrongSecret(t *testing.T) {
	repo := memory.NewClientRepository([]*domain.Client{testClient()})
	auth := memory.NewClientAuthenticator(repo)

	_, err := auth.Authenticate(context.Background(), "client-1", "wrong-secret")
	if err == nil {
		t.Fatal("expected error for wrong secret, got nil")
	}
}

func TestClientAuthenticator_Authenticate_NotFound(t *testing.T) {
	repo := memory.NewClientRepository(nil)
	auth := memory.NewClientAuthenticator(repo)

	_, err := auth.Authenticate(context.Background(), "nonexistent", "secret")
	if err == nil {
		t.Fatal("expected error for nonexistent client, got nil")
	}
}
