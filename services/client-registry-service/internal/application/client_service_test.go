package application_test

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

type fakeClientRepo struct {
	clients map[string]*domain.OAuthClient
}

func newFakeClientRepo() *fakeClientRepo {
	return &fakeClientRepo{clients: make(map[string]*domain.OAuthClient)}
}

func (m *fakeClientRepo) FindByID(_ context.Context, id string) (*domain.OAuthClient, error) {
	c, ok := m.clients[id]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "client not found: "+id)
	}
	return c, nil
}

func (m *fakeClientRepo) Save(_ context.Context, c *domain.OAuthClient) error {
	m.clients[c.ID] = c
	return nil
}

func (m *fakeClientRepo) Update(_ context.Context, c *domain.OAuthClient) error {
	m.clients[c.ID] = c
	return nil
}

func (m *fakeClientRepo) Delete(_ context.Context, id string) error {
	if _, ok := m.clients[id]; !ok {
		return apperrors.New(apperrors.ErrCodeNotFound, "client not found: "+id)
	}
	delete(m.clients, id)
	return nil
}

func (m *fakeClientRepo) List(_ context.Context) ([]*domain.OAuthClient, error) {
	result := make([]*domain.OAuthClient, 0, len(m.clients))
	for _, c := range m.clients {
		result = append(result, c)
	}
	return result, nil
}

// mustHashSecret hashes a plain-text secret with bcrypt for use in test fixtures.
func mustHashSecret(t *testing.T, secret string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("failed to hash test secret: %v", err)
	}
	return string(hash)
}

func TestClientService_CreateClient_Success(t *testing.T) {
	repo := newFakeClientRepo()
	svc := application.NewClientService(repo)

	resp, err := svc.CreateClient(context.Background(), domain.CreateClientRequest{
		Name:       "My App",
		Scopes:     []string{"read", "write"},
		GrantTypes: []string{"client_credentials"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ClientID == "" || resp.ClientSecret == "" {
		t.Error("expected non-empty client_id and client_secret")
	}
	if resp.Name != "My App" {
		t.Errorf("expected name 'My App', got %s", resp.Name)
	}
}

func TestClientService_GetClient_Success(t *testing.T) {
	repo := newFakeClientRepo()
	repo.clients["existing-id"] = &domain.OAuthClient{
		ID:        "existing-id",
		Name:      "Existing Client",
		Active:    true,
		CreatedAt: time.Now(),
	}

	svc := application.NewClientService(repo)
	resp, err := svc.GetClient(context.Background(), "existing-id")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ClientID != "existing-id" {
		t.Errorf("expected client_id existing-id, got %s", resp.ClientID)
	}
}

func TestClientService_GetClient_NotFound(t *testing.T) {
	repo := newFakeClientRepo()
	svc := application.NewClientService(repo)

	_, err := svc.GetClient(context.Background(), "does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing client")
	}
}

func TestClientService_ValidateClient_Valid(t *testing.T) {
	repo := newFakeClientRepo()
	// Secrets are stored as bcrypt hashes — seed the fixture accordingly.
	repo.clients["my-client"] = &domain.OAuthClient{
		ID:     "my-client",
		Secret: mustHashSecret(t, "my-secret"),
		Active: true,
	}

	svc := application.NewClientService(repo)
	resp, err := svc.ValidateClient(context.Background(), domain.ValidateClientRequest{
		ClientID:     "my-client",
		ClientSecret: "my-secret",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Error("expected Valid=true for correct credentials")
	}
}

func TestClientService_ValidateClient_WrongSecret(t *testing.T) {
	repo := newFakeClientRepo()
	// Secrets are stored as bcrypt hashes — seed the fixture accordingly.
	repo.clients["my-client"] = &domain.OAuthClient{
		ID:     "my-client",
		Secret: mustHashSecret(t, "correct-secret"),
		Active: true,
	}

	svc := application.NewClientService(repo)
	resp, err := svc.ValidateClient(context.Background(), domain.ValidateClientRequest{
		ClientID:     "my-client",
		ClientSecret: "wrong-secret",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected Valid=false for wrong secret")
	}
}

func TestClientService_ListClients(t *testing.T) {
	repo := newFakeClientRepo()
	repo.clients["c1"] = &domain.OAuthClient{ID: "c1", Name: "Client 1", Active: true}
	repo.clients["c2"] = &domain.OAuthClient{ID: "c2", Name: "Client 2", Active: true}

	svc := application.NewClientService(repo)
	clients, err := svc.ListClients(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clients) != 2 {
		t.Errorf("expected 2 clients, got %d", len(clients))
	}
}

func TestClientService_DeleteClient_Success(t *testing.T) {
	repo := newFakeClientRepo()
	repo.clients["to-delete"] = &domain.OAuthClient{ID: "to-delete", Name: "Old Client", Active: true}
	svc := application.NewClientService(repo)

	err := svc.DeleteClient(context.Background(), "to-delete")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = svc.GetClient(context.Background(), "to-delete")
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestClientService_DeleteClient_NotFound(t *testing.T) {
	repo := newFakeClientRepo()
	svc := application.NewClientService(repo)

	err := svc.DeleteClient(context.Background(), "nonexistent")
	// The memory repo returns ErrCodeNotFound — DeleteClient propagates it.
	if err == nil {
		t.Error("expected error deleting nonexistent client")
	}
}

func TestClientService_CreateClient_MissingName(t *testing.T) {
	repo := newFakeClientRepo()
	svc := application.NewClientService(repo)

	_, err := svc.CreateClient(context.Background(), domain.CreateClientRequest{
		GrantTypes: []string{"client_credentials"},
	})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}
