package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

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

// TestClientService_CreateClient_PersistsJWKSURI verifies the RFC 7591 §2
// jwks_uri registration field (ADR-0023) round-trips through CreateClient
// into both the response and the stored record — RFC 7523 client-assertion
// verification reads it back via GetClient.
func TestClientService_CreateClient_PersistsJWKSURI(t *testing.T) {
	repo := newFakeClientRepo()
	svc := newSvc(t, repo)

	resp, err := svc.CreateClient(context.Background(), domain.CreateClientRequest{
		Name:       "JWT-Bearer App",
		GrantTypes: []string{"client_credentials"},
		JWKSURI:    "https://client.example.com/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if resp.JWKSURI != "https://client.example.com/.well-known/jwks.json" {
		t.Errorf("response JWKSURI = %q", resp.JWKSURI)
	}

	stored, err := repo.FindByID(context.Background(), resp.ClientID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if stored.JWKSURI != "https://client.example.com/.well-known/jwks.json" {
		t.Errorf("stored JWKSURI = %q", stored.JWKSURI)
	}
}

func TestClientService_GetClient_ReturnsJWKSURI(t *testing.T) {
	repo := newFakeClientRepo()
	repo.clients["existing-id"] = &domain.OAuthClient{
		ID:        "existing-id",
		Name:      "Existing Client",
		Active:    true,
		CreatedAt: time.Now(),
		JWKSURI:   "https://client.example.com/.well-known/jwks.json",
	}

	svc := application.NewClientService(repo)
	resp, err := svc.GetClient(context.Background(), "existing-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.JWKSURI != "https://client.example.com/.well-known/jwks.json" {
		t.Errorf("GetClient JWKSURI = %q", resp.JWKSURI)
	}
}

func TestClientService_CreateClient_JWKSURIOptional(t *testing.T) {
	svc := newSvc(t, newFakeClientRepo())

	resp, err := svc.CreateClient(context.Background(), domain.CreateClientRequest{
		Name:       "Secret-Only App",
		GrantTypes: []string{"client_credentials"},
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if resp.JWKSURI != "" {
		t.Errorf("JWKSURI = %q, want empty when not supplied", resp.JWKSURI)
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

// TestClientService_ValidateClient_PublicClientEmptySecret verifies the
// documented invariant (ADR-0009 / auth-server's CLAUDE.md: "public
// clients (no secret, PKCE-only) ... work") — a public client has no
// stored secret, so it must validate successfully with an empty
// client_secret. Before this fix, ValidateClient short-circuited to
// Valid=false for ANY empty secret regardless of client type, which
// made public clients unable to authenticate through this path at all.
func TestClientService_ValidateClient_PublicClientEmptySecret(t *testing.T) {
	repo := newFakeClientRepo()
	repo.clients["public-client"] = &domain.OAuthClient{
		ID:     "public-client",
		Type:   domain.ClientTypePublic,
		Active: true,
	}

	svc := newSvc(t, repo)
	resp, err := svc.ValidateClient(context.Background(), domain.ValidateClientRequest{
		ClientID:     "public-client",
		ClientSecret: "",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Error("expected Valid=true for a public client presenting an empty secret")
	}
}

// TestClientService_ValidateClient_PublicClientInactive verifies the
// Active-flag invariant still applies to public clients.
func TestClientService_ValidateClient_PublicClientInactive(t *testing.T) {
	repo := newFakeClientRepo()
	repo.clients["public-client"] = &domain.OAuthClient{
		ID:     "public-client",
		Type:   domain.ClientTypePublic,
		Active: false,
	}

	svc := newSvc(t, repo)
	resp, err := svc.ValidateClient(context.Background(), domain.ValidateClientRequest{
		ClientID:     "public-client",
		ClientSecret: "",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected Valid=false for an inactive public client")
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

// --- Audit emission (ADR-0018 / ADR-0019) ---

type captureSink struct {
	events []audit.Event
	err    error
}

func (c *captureSink) Sink(_ context.Context, e audit.Event) error {
	c.events = append(c.events, e)
	return c.err
}

var errAuditFailure = errors.New("simulated audit transport failure")

func TestCreateClient_EmitsClientRegistered(t *testing.T) {
	sink := &captureSink{}
	svc := newSvc(t, newFakeClientRepo()).
		WithAudit(audit.New(sink), "client-registry-service")

	resp, err := svc.CreateClient(context.Background(), domain.CreateClientRequest{
		Name:       "test-client",
		ClientType: "confidential",
		GrantTypes: []string{"client_credentials"},
		Scopes:     []string{"read"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	assertClientRegisteredEvent(t, sink.events[0], resp.ClientID)
}

// assertClientRegisteredEvent verifies every field on a
// client_registered event. Extracted from the test body so the flat
// list of independent assertions does not push the test's cyclomatic
// complexity past the gocyclo budget.
func assertClientRegisteredEvent(t *testing.T, e audit.Event, wantClientID string) {
	t.Helper()
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"EventType", e.EventType, "client_registered"},
		{"ActorID", e.ActorID, wantClientID},
		{"SubjectID", e.SubjectID, wantClientID},
		{"ResourceKind", string(e.ResourceKind), string(audit.ResourceKindEndpoint)},
		{"ResourcePath", e.ResourcePath, "client-registry-service/endpoint/register"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("event.%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	if name, _ := e.Attrs["name"].(string); name != "test-client" {
		t.Errorf("attrs.name = %v, want test-client", e.Attrs["name"])
	}
	if ct, _ := e.Attrs["client_type"].(string); ct != "confidential" {
		t.Errorf("attrs.client_type = %v, want confidential", e.Attrs["client_type"])
	}
}

func TestCreateClient_AuditFailureSurfaces(t *testing.T) {
	sink := &captureSink{err: errAuditFailure}
	svc := newSvc(t, newFakeClientRepo()).
		WithAudit(audit.New(sink), "client-registry-service")

	_, err := svc.CreateClient(context.Background(), domain.CreateClientRequest{
		Name:       "test-client",
		GrantTypes: []string{"client_credentials"},
	})
	if err == nil {
		t.Fatal("expected error when audit emit fails")
	}
	if !errors.Is(err, errAuditFailure) {
		t.Errorf("expected wrapped audit error, got %v", err)
	}
}

func TestDeleteClient_EmitsClientDeleted(t *testing.T) {
	repo := newFakeClientRepo()
	repo.clients["c-1"] = &domain.OAuthClient{
		ID:        "c-1",
		Name:      "to-delete",
		CreatedAt: time.Now(),
		Active:    true,
	}
	sink := &captureSink{}
	svc := newSvc(t, repo).
		WithAudit(audit.New(sink), "client-registry-service")

	if err := svc.DeleteClient(context.Background(), "c-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	e := sink.events[0]
	if e.EventType != "client_deleted" {
		t.Errorf("event_type = %q, want client_deleted", e.EventType)
	}
	if e.ActorID != "c-1" {
		t.Errorf("actor_id = %q, want c-1", e.ActorID)
	}
	if e.ResourcePath != "client-registry-service/endpoint/delete" {
		t.Errorf("resource_path = %q, want client-registry-service/endpoint/delete", e.ResourcePath)
	}
}

func TestDeleteClient_AuditFailureSurfaces(t *testing.T) {
	repo := newFakeClientRepo()
	repo.clients["c-1"] = &domain.OAuthClient{ID: "c-1", Active: true}
	sink := &captureSink{err: errAuditFailure}
	svc := newSvc(t, repo).
		WithAudit(audit.New(sink), "client-registry-service")

	err := svc.DeleteClient(context.Background(), "c-1")
	if err == nil {
		t.Fatal("expected error when audit emit fails")
	}
	if !errors.Is(err, errAuditFailure) {
		t.Errorf("expected wrapped audit error, got %v", err)
	}
}

func TestCreateClient_DefaultsActorTypeToService(t *testing.T) {
	repo := newFakeClientRepo()
	svc := newSvc(t, repo)

	resp, err := svc.CreateClient(context.Background(), domain.CreateClientRequest{
		Name:       "no-actor-type",
		GrantTypes: []string{"client_credentials"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ActorType != string(domain.ActorTypeService) {
		t.Errorf("ActorType = %q, want service (default)", resp.ActorType)
	}
	stored := repo.clients[resp.ClientID]
	if stored.ActorType != domain.ActorTypeService {
		t.Errorf("stored ActorType = %q, want service", stored.ActorType)
	}
}

func TestCreateClient_PersistsActorTypeAgent(t *testing.T) {
	repo := newFakeClientRepo()
	svc := newSvc(t, repo)

	resp, err := svc.CreateClient(context.Background(), domain.CreateClientRequest{
		Name:       "agent-claude",
		ActorType:  "agent",
		GrantTypes: []string{"client_credentials"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ActorType != string(domain.ActorTypeAgent) {
		t.Errorf("ActorType = %q, want agent", resp.ActorType)
	}
	stored := repo.clients[resp.ClientID]
	if stored.ActorType != domain.ActorTypeAgent {
		t.Errorf("stored ActorType = %q, want agent", stored.ActorType)
	}
}

func TestCreateClient_UnknownActorTypeFailsClosed(t *testing.T) {
	// ADR-0015 fail-closed rule: unknown wire values must not silently
	// grant agent semantics.
	repo := newFakeClientRepo()
	svc := newSvc(t, repo)

	resp, err := svc.CreateClient(context.Background(), domain.CreateClientRequest{
		Name:       "weird",
		ActorType:  "robot",
		GrantTypes: []string{"client_credentials"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ActorType != string(domain.ActorTypeService) {
		t.Errorf("ActorType = %q, want service (fail-closed default)", resp.ActorType)
	}
}

func TestCreateClient_EmitsAgentRegistered(t *testing.T) {
	sink := &captureSink{}
	svc := newSvc(t, newFakeClientRepo()).
		WithAudit(audit.New(sink), "client-registry-service")

	resp, err := svc.CreateClient(context.Background(), domain.CreateClientRequest{
		Name:       "agent-claude",
		ActorType:  "agent",
		GrantTypes: []string{"client_credentials"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	e := sink.events[0]
	if e.EventType != "agent_registered" {
		t.Errorf("event_type = %q, want agent_registered", e.EventType)
	}
	if e.ActorType != audit.ActorTypeAgent {
		t.Errorf("actor_type = %q, want agent", e.ActorType)
	}
	if e.ActorID != resp.ClientID {
		t.Errorf("actor_id = %q, want %q", e.ActorID, resp.ClientID)
	}
	if at, _ := e.Attrs["actor_type"].(string); at != "agent" {
		t.Errorf("attrs.actor_type = %v, want agent", e.Attrs["actor_type"])
	}
}

func TestCreateClient_EmitsClientRegistered_NonAgent(t *testing.T) {
	// Verify that the default (service) path still emits client_registered.
	sink := &captureSink{}
	svc := newSvc(t, newFakeClientRepo()).
		WithAudit(audit.New(sink), "client-registry-service")

	if _, err := svc.CreateClient(context.Background(), domain.CreateClientRequest{
		Name:       "service-client",
		GrantTypes: []string{"client_credentials"},
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	if sink.events[0].EventType != "client_registered" {
		t.Errorf("event_type = %q, want client_registered", sink.events[0].EventType)
	}
	if sink.events[0].ActorType != audit.ActorTypeService {
		t.Errorf("actor_type = %q, want service", sink.events[0].ActorType)
	}
}

func TestGetClient_ReturnsActorType(t *testing.T) {
	repo := newFakeClientRepo()
	repo.clients["c-1"] = &domain.OAuthClient{
		ID:        "c-1",
		Name:      "agent-claude",
		Type:      domain.ClientTypeConfidential,
		ActorType: domain.ActorTypeAgent,
		Active:    true,
		CreatedAt: time.Now(),
	}
	svc := newSvc(t, repo)

	resp, err := svc.GetClient(context.Background(), "c-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ActorType != "agent" {
		t.Errorf("ActorType = %q, want agent", resp.ActorType)
	}
}

func TestGetClient_EmptyStoredActorTypeSurfacesAsService(t *testing.T) {
	// Records persisted before ADR-0015 have an empty ActorType; the
	// fail-closed normalization must surface them as "service".
	repo := newFakeClientRepo()
	repo.clients["c-1"] = &domain.OAuthClient{
		ID:        "c-1",
		Name:      "legacy",
		Type:      domain.ClientTypeConfidential,
		ActorType: "",
		Active:    true,
		CreatedAt: time.Now(),
	}
	svc := newSvc(t, repo)

	resp, err := svc.GetClient(context.Background(), "c-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ActorType != "service" {
		t.Errorf("ActorType = %q, want service (fail-closed default)", resp.ActorType)
	}
}

func TestClientService_WithAudit_NilEmitterPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = newSvc(t, newFakeClientRepo()).WithAudit(nil, "client-registry-service")
}
