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

// FindByID returns the stored pointer directly without deep-copying; this is intentional
// for tests — it lets test assertions read mutated fields without round-tripping through
// the repo. Do not promote this fake to production code.
func (m *fakeClientRepo) FindByID(_ context.Context, id string) (*domain.OAuthClient, error) {
	c, ok := m.clients[id]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "client not found: "+id)
	}
	return c, nil
}

func (m *fakeClientRepo) Save(_ context.Context, c *domain.OAuthClient) error {
	if _, exists := m.clients[c.ID]; exists {
		return apperrors.New(apperrors.ErrCodeConflict, "client already exists")
	}
	m.clients[c.ID] = c
	return nil
}

func (m *fakeClientRepo) Update(_ context.Context, c *domain.OAuthClient) error {
	if _, ok := m.clients[c.ID]; !ok {
		return apperrors.New(apperrors.ErrCodeNotFound, "client not found: "+c.ID)
	}
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

// newSvc creates a ClientService with bcrypt.MinCost for fast tests.
func newSvc(t *testing.T, repo *fakeClientRepo) *application.ClientService {
	t.Helper()
	svc, err := application.NewClientServiceWithCost(repo, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("NewClientServiceWithCost: %v", err)
	}
	return svc
}

// TestNewClientServiceWithCost_InvalidCost_ReturnsError verifies that a bcrypt cost
// below MinCost is rejected at construction time rather than panicking later.
func TestNewClientServiceWithCost_InvalidCost_ReturnsError(t *testing.T) {
	_, err := application.NewClientServiceWithCost(newFakeClientRepo(), bcrypt.MinCost-1)
	if err == nil {
		t.Fatal("expected error for cost below MinCost, got nil")
	}
}

// errFindRepo is a fake that returns a configurable error from FindByID, used to
// test error propagation paths that the standard fakeClientRepo cannot trigger.
type errFindRepo struct {
	fakeClientRepo
	findErr error
}

func (m *errFindRepo) FindByID(_ context.Context, _ string) (*domain.OAuthClient, error) {
	return nil, m.findErr
}

func TestClientService_CreateClient_Success(t *testing.T) {
	svc := newSvc(t, newFakeClientRepo())

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

// TestClientService_CreateClient_SecretRoundTrip verifies that the plain-text
// secret returned by CreateClient can be used to validate the client immediately.
func TestClientService_CreateClient_SecretRoundTrip(t *testing.T) {
	repo := newFakeClientRepo()
	svc := newSvc(t, repo)

	created, err := svc.CreateClient(context.Background(), domain.CreateClientRequest{
		Name:       "App",
		GrantTypes: []string{"client_credentials"},
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	resp, err := svc.ValidateClient(context.Background(), domain.ValidateClientRequest{
		ClientID:     created.ClientID,
		ClientSecret: created.ClientSecret,
	})
	if err != nil {
		t.Fatalf("ValidateClient: %v", err)
	}
	if !resp.Valid {
		t.Error("expected Valid=true for freshly-created client using returned secret")
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
	svc := application.NewClientService(newFakeClientRepo())

	_, err := svc.GetClient(context.Background(), "does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing client")
	}
}

func TestClientService_ValidateClient_Valid(t *testing.T) {
	repo := newFakeClientRepo()
	repo.clients["my-client"] = &domain.OAuthClient{
		ID:     "my-client",
		Secret: mustHashSecret(t, "my-secret"),
		Active: true,
	}

	svc := newSvc(t, repo)
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
	repo.clients["my-client"] = &domain.OAuthClient{
		ID:     "my-client",
		Secret: mustHashSecret(t, "correct-secret"),
		Active: true,
	}

	svc := newSvc(t, repo)
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

// TestClientService_ValidateClient_InactiveClient verifies the documented invariant:
// inactive clients fail validation even with correct credentials.
func TestClientService_ValidateClient_InactiveClient(t *testing.T) {
	repo := newFakeClientRepo()
	repo.clients["inactive"] = &domain.OAuthClient{
		ID:     "inactive",
		Secret: mustHashSecret(t, "secret"),
		Active: false,
	}

	svc := newSvc(t, repo)
	resp, err := svc.ValidateClient(context.Background(), domain.ValidateClientRequest{
		ClientID:     "inactive",
		ClientSecret: "secret",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected Valid=false for inactive client with correct credentials")
	}
}

// TestClientService_ValidateClient_ClientNotFound verifies that a missing client
// returns Valid=false without an error — avoids leaking whether a client ID exists.
func TestClientService_ValidateClient_ClientNotFound(t *testing.T) {
	svc := newSvc(t, newFakeClientRepo())

	resp, err := svc.ValidateClient(context.Background(), domain.ValidateClientRequest{
		ClientID:     "ghost",
		ClientSecret: "anything",
	})

	if err != nil {
		t.Fatalf("expected no error for missing client, got: %v", err)
	}
	if resp.Valid {
		t.Error("expected Valid=false for non-existent client")
	}
}

// TestClientService_ValidateClient_EmptyClientID verifies that an empty client ID
// returns Valid=false without an error — the not-found path handles the empty lookup.
func TestClientService_ValidateClient_EmptyClientID(t *testing.T) {
	svc := newSvc(t, newFakeClientRepo())

	resp, err := svc.ValidateClient(context.Background(), domain.ValidateClientRequest{
		ClientID:     "",
		ClientSecret: "anything",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected Valid=false for empty client_id")
	}
}

// TestClientService_ValidateClient_EmptySecret verifies that an empty secret returns
// Valid=false without an error or unnecessary bcrypt work.
func TestClientService_ValidateClient_EmptySecret(t *testing.T) {
	repo := newFakeClientRepo()
	repo.clients["my-client"] = &domain.OAuthClient{
		ID:     "my-client",
		Secret: mustHashSecret(t, "real-secret"),
		Active: true,
	}

	svc := newSvc(t, repo)
	resp, err := svc.ValidateClient(context.Background(), domain.ValidateClientRequest{
		ClientID:     "my-client",
		ClientSecret: "",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected Valid=false for empty client_secret")
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
		t.Fatalf("expected 2 clients, got %d", len(clients))
	}

	// Verify both expected IDs are present (map iteration is non-deterministic).
	got := make(map[string]bool, len(clients))
	for _, c := range clients {
		got[c.ClientID] = true
	}
	if !got["c1"] || !got["c2"] {
		t.Errorf("expected client IDs c1 and c2, got %v", got)
	}
}

// TestClientService_ListClients_Empty verifies that an empty repository returns an
// empty slice (not nil), so JSON serialisation produces [] not null.
func TestClientService_ListClients_Empty(t *testing.T) {
	svc := application.NewClientService(newFakeClientRepo())

	clients, err := svc.ListClients(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clients == nil {
		t.Error("expected non-nil empty slice, got nil")
	}
	if len(clients) != 0 {
		t.Errorf("expected 0 clients, got %d", len(clients))
	}
}

func TestClientService_DeleteClient_Success(t *testing.T) {
	repo := newFakeClientRepo()
	repo.clients["to-delete"] = &domain.OAuthClient{ID: "to-delete", Name: "Old Client", Active: true}
	svc := application.NewClientService(repo)

	if err := svc.DeleteClient(context.Background(), "to-delete"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := svc.GetClient(context.Background(), "to-delete"); err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestClientService_DeleteClient_NotFound(t *testing.T) {
	svc := application.NewClientService(newFakeClientRepo())

	err := svc.DeleteClient(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error deleting nonexistent client")
	}
}

func TestClientService_CreateClient_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     domain.CreateClientRequest
		wantErr bool
	}{
		{
			name:    "missing name",
			req:     domain.CreateClientRequest{GrantTypes: []string{"client_credentials"}},
			wantErr: true,
		},
		{
			name:    "missing grant types",
			req:     domain.CreateClientRequest{Name: "App"},
			wantErr: true,
		},
		{
			name:    "blank grant type element",
			req:     domain.CreateClientRequest{Name: "App", GrantTypes: []string{""}},
			wantErr: true,
		},
		{
			name:    "valid request",
			req:     domain.CreateClientRequest{Name: "App", GrantTypes: []string{"client_credentials"}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newSvc(t, newFakeClientRepo())
			_, err := svc.CreateClient(context.Background(), tt.req)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestClientService_CreateClient_TimestampsMatch verifies that CreatedAt and
// UpdatedAt are identical on a newly created client (a single time.Now() call).
func TestClientService_CreateClient_TimestampsMatch(t *testing.T) {
	repo := newFakeClientRepo()
	svc := newSvc(t, repo)

	resp, err := svc.CreateClient(context.Background(), domain.CreateClientRequest{
		Name:       "App",
		GrantTypes: []string{"client_credentials"},
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	stored, err := repo.FindByID(context.Background(), resp.ClientID)
	if err != nil {
		t.Fatalf("FindByID after create: %v", err)
	}
	if !stored.CreatedAt.Equal(stored.UpdatedAt) {
		t.Errorf("CreatedAt (%v) != UpdatedAt (%v) on newly created client; both should be set from a single time.Now() call",
			stored.CreatedAt, stored.UpdatedAt)
	}
}

// TestClientService_ValidateClient_RepoError_PropagatesError verifies that a
// non-not-found error from the repository propagates as an error (not Valid=false).
func TestClientService_ValidateClient_RepoError_PropagatesError(t *testing.T) {
	base := newFakeClientRepo()
	repo := &errFindRepo{
		fakeClientRepo: *base,
		findErr:        apperrors.New(apperrors.ErrCodeInternal, "database unavailable"),
	}
	svc := application.NewClientService(repo)

	_, err := svc.ValidateClient(context.Background(), domain.ValidateClientRequest{
		ClientID:     "any",
		ClientSecret: "any",
	})
	if err == nil {
		t.Fatal("expected error to propagate from repo, got nil")
	}
}
