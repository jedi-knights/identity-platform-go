package application_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/audit"

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

	strategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour, nil)

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

	strategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour, nil)

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

	strategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour, nil)

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

	strategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour, nil)

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

	strategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour, nil)

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
	return application.NewRefreshTokenStrategy(auth, tokenRepo, refreshRepo, &mockTokenGen{}, nil, time.Hour, 7*24*time.Hour, nil)
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

	ccStrategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour, nil)
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

func TestGrantStrategyRegistry_Handle_EmitsTokenIssued(t *testing.T) {
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	tokenGen := &mockTokenGen{}

	auth.clients["c1"] = newTestClient(
		"c1", "secret",
		[]string{"read"},
		[]domain.GrantType{domain.GrantTypeClientCredentials},
	)

	ccStrategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour, nil)
	captured := &captureSink{}
	registry := application.
		NewGrantStrategyRegistry(ccStrategy).
		WithAudit(audit.New(captured), "auth-server")

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
	if len(captured.events) != 1 {
		t.Fatalf("expected 1 emitted event, got %d", len(captured.events))
	}
	assertTokenIssuedEvent(t, captured.events[0])
}

// assertTokenIssuedEvent verifies every field on the emitted
// token_issued event. Extracted from the test body so the flat list of
// independent assertions does not push the test's cyclomatic
// complexity past the gocyclo budget.
func assertTokenIssuedEvent(t *testing.T, e audit.Event) {
	t.Helper()
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"EventType", e.EventType, "token_issued"},
		{"Service", e.Service, "auth-server"},
		{"ActorType", string(e.ActorType), string(audit.ActorTypeService)},
		{"ActorID", e.ActorID, "c1"},
		{"ResourceKind", string(e.ResourceKind), string(audit.ResourceKindToken)},
		{"ResourcePath", e.ResourcePath, "auth-server/token/access"},
		{"Decision", string(e.Decision), string(audit.DecisionAllow)},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("event.%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	if gt, _ := e.Attrs["grant_type"].(string); gt != "client_credentials" {
		t.Errorf("attrs.grant_type = %v, want client_credentials", e.Attrs["grant_type"])
	}
}

func TestGrantStrategyRegistry_Handle_FailsWhenAuditFails(t *testing.T) {
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	tokenGen := &mockTokenGen{}

	auth.clients["c1"] = newTestClient(
		"c1", "secret",
		[]string{"read"},
		[]domain.GrantType{domain.GrantTypeClientCredentials},
	)

	ccStrategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour, nil)
	registry := application.
		NewGrantStrategyRegistry(ccStrategy).
		WithAudit(audit.New(&captureSink{err: errAuditFailure}), "auth-server")

	_, err := registry.Handle(context.Background(), domain.GrantRequest{
		GrantType:    domain.GrantTypeClientCredentials,
		ClientID:     "c1",
		ClientSecret: "secret",
	})
	if err == nil {
		t.Fatal("expected error when audit sink fails (ADR-0019 paid event policy)")
	}
	if !errors.Is(err, errAuditFailure) {
		t.Errorf("expected wrapped audit error, got %v", err)
	}
}

func TestGrantStrategyRegistry_Handle_EmitsAgentActorType(t *testing.T) {
	// ADR-0015: when the authenticated client is classified as an agent,
	// the issued token and the token_issued event must carry actor_type=agent
	// and agent_id from the client record.
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	tokenGen := &mockTokenGen{}

	agentClient := newTestClient(
		"agent-claude", "secret",
		[]string{"read"},
		[]domain.GrantType{domain.GrantTypeClientCredentials},
	)
	agentClient.ActorType = domain.ActorTypeAgent
	auth.clients["agent-claude"] = agentClient

	ccStrategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour, nil)
	captured := &captureSink{}
	registry := application.
		NewGrantStrategyRegistry(ccStrategy).
		WithAudit(audit.New(captured), "auth-server")

	if _, err := registry.Handle(context.Background(), domain.GrantRequest{
		GrantType:    domain.GrantTypeClientCredentials,
		ClientID:     "agent-claude",
		ClientSecret: "secret",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(captured.events) != 1 {
		t.Fatalf("expected 1 emitted event, got %d", len(captured.events))
	}
	e := captured.events[0]
	if e.ActorType != audit.ActorTypeAgent {
		t.Errorf("actor_type = %q, want agent", e.ActorType)
	}
	if at, _ := e.Attrs["actor_type"].(string); at != "agent" {
		t.Errorf("attrs.actor_type = %v, want agent", e.Attrs["actor_type"])
	}
	if aid, _ := e.Attrs["agent_id"].(string); aid != "agent-claude" {
		t.Errorf("attrs.agent_id = %v, want agent-claude", e.Attrs["agent_id"])
	}
}

func TestGrantStrategyRegistry_Handle_LegacyEmptyActorTypeFailsClosed(t *testing.T) {
	// ADR-0015 fail-closed: a client with empty ActorType (pre-ADR-0015
	// record) must surface as service, not as empty.
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	tokenGen := &mockTokenGen{}

	legacy := newTestClient(
		"legacy-c1", "secret",
		[]string{"read"},
		[]domain.GrantType{domain.GrantTypeClientCredentials},
	)
	// ActorType deliberately not set (pre-ADR-0015 record).
	auth.clients["legacy-c1"] = legacy

	ccStrategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour, nil)
	captured := &captureSink{}
	registry := application.
		NewGrantStrategyRegistry(ccStrategy).
		WithAudit(audit.New(captured), "auth-server")

	if _, err := registry.Handle(context.Background(), domain.GrantRequest{
		GrantType:    domain.GrantTypeClientCredentials,
		ClientID:     "legacy-c1",
		ClientSecret: "secret",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(captured.events) != 1 {
		t.Fatalf("expected 1 emitted event, got %d", len(captured.events))
	}
	if captured.events[0].ActorType != audit.ActorTypeService {
		t.Errorf("actor_type = %q, want service (fail-closed)", captured.events[0].ActorType)
	}
}

func TestGrantStrategyRegistry_WithAudit_NilEmitterPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = application.NewGrantStrategyRegistry().WithAudit(nil, "auth-server")
}

// captureSink records every event passed to it and optionally returns a
// preconfigured error. It satisfies audit.Sink so the registry can be
// driven without a real transport.
type captureSink struct {
	events []audit.Event
	err    error
}

func (c *captureSink) Sink(_ context.Context, e audit.Event) error {
	c.events = append(c.events, e)
	return c.err
}

var errAuditFailure = errors.New("simulated audit transport failure")

func TestClientCredentialsStrategy_Supports(t *testing.T) {
	auth := newMockClientAuthenticator()
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	tokenGen := &mockTokenGen{}

	ccStrategy := application.NewClientCredentialsStrategy(auth, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour, nil)

	if !ccStrategy.Supports(domain.GrantTypeClientCredentials) {
		t.Error("expected client_credentials to be supported")
	}
	if ccStrategy.Supports(domain.GrantTypeAuthorizationCode) {
		t.Error("expected authorization_code not to be supported by cc strategy")
	}
}

// The previous stub test (TestAuthorizationCodeStrategy_Handle_ReturnsNotImplemented)
// expected ErrUnsupportedGrantType. ADR-0009 implements the grant; the full
// behaviour is covered by TestAuthorizationCodeStrategy_Handle_* in
// authcode_strategy_test.go.
