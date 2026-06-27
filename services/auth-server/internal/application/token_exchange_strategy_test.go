package application_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// mockTokenValidator implements application.TokenValidator. Tokens are
// indexed by their raw string so the test can stage validation
// behaviour up front and have the strategy resolve the right token at
// validation time.
type mockTokenValidator struct {
	tokens map[string]*domain.Token
	err    error
}

func newMockTokenValidator() *mockTokenValidator {
	return &mockTokenValidator{tokens: make(map[string]*domain.Token)}
}

func (m *mockTokenValidator) Validate(_ context.Context, raw string) (*domain.Token, error) {
	if m.err != nil {
		return nil, m.err
	}
	t, ok := m.tokens[raw]
	if !ok {
		return nil, errors.New("token not found")
	}
	return t, nil
}

func newExchangeStrategy(t *testing.T, opts ...func(*application.TokenExchangeStrategyConfig)) (*application.TokenExchangeStrategy, *mockClientAuthenticator, *mockTokenValidator, *mockTokenRepo) {
	t.Helper()
	auth := newMockClientAuthenticator()
	val := newMockTokenValidator()
	repo := newMockTokenRepo()
	cfg := application.TokenExchangeStrategyConfig{
		ClientAuth:     auth,
		TokenValidator: val,
		TokenRepo:      repo,
		TokenGen:       &mockTokenGen{},
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return application.NewTokenExchangeStrategy(cfg), auth, val, repo
}

func confidentialExchangeClient() *domain.Client {
	c := newTestClient("client-A", "secret", []string{"read", "write"}, []domain.GrantType{domain.GrantTypeTokenExchange})
	c.Type = domain.ClientTypeConfidential
	return c
}

func publicExchangeClient() *domain.Client {
	c := newTestClient("client-pub", "", []string{"read"}, []domain.GrantType{domain.GrantTypeTokenExchange})
	c.Type = domain.ClientTypePublic
	return c
}

func validSubjectToken() *domain.Token {
	return &domain.Token{
		ID:        "sub-1",
		ClientID:  "originator",
		Subject:   "user-omar",
		Scopes:    []string{"read", "write"},
		ActorType: domain.ActorTypeUser,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IssuedAt:  time.Now(),
		Raw:       "subject-token-raw",
	}
}

func validExchangeRequest() domain.GrantRequest {
	return domain.GrantRequest{
		GrantType:        domain.GrantTypeTokenExchange,
		ClientID:         "client-A",
		ClientSecret:     "secret",
		SubjectToken:     "subject-token-raw",
		SubjectTokenType: domain.TokenTypeURNAccessToken,
	}
}

func TestTokenExchange_Supports(t *testing.T) {
	s, _, _, _ := newExchangeStrategy(t)
	if !s.Supports(domain.GrantTypeTokenExchange) {
		t.Errorf("must support token-exchange grant")
	}
	if s.Supports(domain.GrantTypeClientCredentials) {
		t.Errorf("must not support client_credentials")
	}
}

func TestTokenExchange_Handle_Success(t *testing.T) {
	s, auth, val, repo := newExchangeStrategy(t)
	auth.clients["client-A"] = confidentialExchangeClient()
	val.tokens["subject-token-raw"] = validSubjectToken()

	resp, err := s.Handle(context.Background(), validExchangeRequest())
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.AccessToken != "mock-token-123" {
		t.Errorf("access_token = %q", resp.AccessToken)
	}
	if resp.TokenType != string(domain.TokenTypeBearer) {
		t.Errorf("token_type = %q", resp.TokenType)
	}
	if resp.IssuedTokenType != domain.TokenTypeURNAccessToken {
		t.Errorf("issued_token_type = %q", resp.IssuedTokenType)
	}
	if resp.Subject != "user-omar" {
		t.Errorf("subject = %q, want user-omar", resp.Subject)
	}
	if len(repo.tokens) != 1 {
		t.Errorf("token was not persisted; repo size = %d", len(repo.tokens))
	}
}

func TestTokenExchange_Handle_BuildsActChain(t *testing.T) {
	s, auth, val, repo := newExchangeStrategy(t)
	caller := confidentialExchangeClient()
	caller.ActorType = domain.ActorTypeAgent
	auth.clients["client-A"] = caller
	val.tokens["subject-token-raw"] = validSubjectToken()

	resp, err := s.Handle(context.Background(), validExchangeRequest())
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	// The persisted token (not the response) carries the chain.
	stored := repo.tokens["mock-token-123"]
	if stored == nil {
		t.Fatal("expected token to be persisted")
	}
	if stored.Act == nil {
		t.Fatal("expected Act chain to be populated")
	}
	if stored.Act.Sub != "client-A" {
		t.Errorf("outermost actor sub = %q, want client-A", stored.Act.Sub)
	}
	if stored.Act.Depth() != 1 {
		t.Errorf("chain depth = %d, want 1 (no actor_token, no subject chain)", stored.Act.Depth())
	}
	if resp.ActorType != domain.ActorTypeAgent {
		t.Errorf("resp ActorType = %q, want agent", resp.ActorType)
	}
}

func TestTokenExchange_Handle_PrependsActorToken(t *testing.T) {
	s, auth, val, repo := newExchangeStrategy(t)
	auth.clients["client-A"] = confidentialExchangeClient()
	val.tokens["subject-token-raw"] = validSubjectToken()
	actorToken := &domain.Token{
		ID:        "act-1",
		ClientID:  "agent-planner",
		Subject:   "agent-planner",
		Scopes:    []string{"read"},
		ActorType: domain.ActorTypeAgent,
		AgentID:   "agent-planner",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Raw:       "actor-token-raw",
	}
	val.tokens["actor-token-raw"] = actorToken

	req := validExchangeRequest()
	req.ActorToken = "actor-token-raw"
	req.ActorTokenType = domain.TokenTypeURNAccessToken

	resp, err := s.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.ActorType != domain.ActorTypeAgent || resp.AgentID != "agent-planner" {
		t.Errorf("actor identity not copied from actor_token; got actor_type=%q agent_id=%q", resp.ActorType, resp.AgentID)
	}
	stored := repo.tokens["mock-token-123"]
	if stored == nil {
		t.Fatal("expected token to be persisted")
	}
	if stored.Act == nil || stored.Act.Sub != "agent-planner" {
		t.Errorf("outermost actor must be the actor_token's principal; got %+v", stored.Act)
	}
}

func TestTokenExchange_Handle_PreservesSubjectChain(t *testing.T) {
	s, auth, val, repo := newExchangeStrategy(t)
	auth.clients["client-A"] = confidentialExchangeClient()
	subject := validSubjectToken()
	// The subject_token already has a chain from a prior exchange.
	subject.Act = &domain.Actor{Sub: "prior-actor"}
	val.tokens["subject-token-raw"] = subject

	if _, err := s.Handle(context.Background(), validExchangeRequest()); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	stored := repo.tokens["mock-token-123"]
	if stored == nil {
		t.Fatal("expected token to be persisted")
	}
	if stored.Act == nil || stored.Act.Sub != "client-A" {
		t.Fatalf("outermost actor = %+v", stored.Act)
	}
	if stored.Act.Act == nil || stored.Act.Act.Sub != "prior-actor" {
		t.Errorf("subject_token's act chain dropped; got %+v", stored.Act.Act)
	}
}

func TestTokenExchange_Handle_RejectsMissingSubjectToken(t *testing.T) {
	s, auth, _, _ := newExchangeStrategy(t)
	auth.clients["client-A"] = confidentialExchangeClient()
	req := validExchangeRequest()
	req.SubjectToken = ""
	_, err := s.Handle(context.Background(), req)
	if !errors.Is(err, application.ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest", err)
	}
}

func TestTokenExchange_Handle_RejectsMissingSubjectTokenType(t *testing.T) {
	s, auth, _, _ := newExchangeStrategy(t)
	auth.clients["client-A"] = confidentialExchangeClient()
	req := validExchangeRequest()
	req.SubjectTokenType = ""
	_, err := s.Handle(context.Background(), req)
	if !errors.Is(err, application.ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest", err)
	}
}

func TestTokenExchange_Handle_RejectsUnknownSubjectTokenType(t *testing.T) {
	s, auth, _, _ := newExchangeStrategy(t)
	auth.clients["client-A"] = confidentialExchangeClient()
	req := validExchangeRequest()
	req.SubjectTokenType = domain.TokenTypeURNJWT
	_, err := s.Handle(context.Background(), req)
	if !errors.Is(err, application.ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest", err)
	}
}

func TestTokenExchange_Handle_RejectsUnknownActorTokenType(t *testing.T) {
	s, auth, _, _ := newExchangeStrategy(t)
	auth.clients["client-A"] = confidentialExchangeClient()
	req := validExchangeRequest()
	req.ActorToken = "actor"
	req.ActorTokenType = domain.TokenTypeURNJWT
	_, err := s.Handle(context.Background(), req)
	if !errors.Is(err, application.ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest", err)
	}
}

func TestTokenExchange_Handle_RejectsUnknownRequestedTokenType(t *testing.T) {
	s, auth, _, _ := newExchangeStrategy(t)
	auth.clients["client-A"] = confidentialExchangeClient()
	req := validExchangeRequest()
	req.RequestedTokenType = domain.TokenTypeURNJWT
	_, err := s.Handle(context.Background(), req)
	if !errors.Is(err, application.ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest", err)
	}
}

func TestTokenExchange_Handle_RejectsInvalidSubjectToken(t *testing.T) {
	s, auth, _, _ := newExchangeStrategy(t)
	auth.clients["client-A"] = confidentialExchangeClient()
	_, err := s.Handle(context.Background(), validExchangeRequest())
	if !errors.Is(err, application.ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest", err)
	}
}

func TestTokenExchange_Handle_RejectsUnauthorizedClient(t *testing.T) {
	s, auth, val, _ := newExchangeStrategy(t)
	// Client does not list token-exchange among its allowed grants.
	c := confidentialExchangeClient()
	c.GrantTypes = []domain.GrantType{domain.GrantTypeClientCredentials}
	auth.clients["client-A"] = c
	val.tokens["subject-token-raw"] = validSubjectToken()
	_, err := s.Handle(context.Background(), validExchangeRequest())
	if !errors.Is(err, application.ErrUnauthorizedClient) {
		t.Errorf("err = %v, want ErrUnauthorizedClient", err)
	}
}

func TestTokenExchange_Handle_PublicClientRejectsOthersSubjectToken(t *testing.T) {
	s, auth, val, _ := newExchangeStrategy(t)
	auth.clients["client-pub"] = publicExchangeClient()
	// Subject token was issued to a different client.
	subject := validSubjectToken()
	subject.ClientID = "someone-else"
	val.tokens["subject-token-raw"] = subject

	req := validExchangeRequest()
	req.ClientID = "client-pub"
	req.ClientSecret = ""
	_, err := s.Handle(context.Background(), req)
	if !errors.Is(err, application.ErrUnauthorizedClient) {
		t.Errorf("err = %v, want ErrUnauthorizedClient", err)
	}
}

func TestTokenExchange_Handle_PublicClientAcceptsOwnSubjectToken(t *testing.T) {
	s, auth, val, _ := newExchangeStrategy(t)
	auth.clients["client-pub"] = publicExchangeClient()
	subject := validSubjectToken()
	subject.ClientID = "client-pub"
	val.tokens["subject-token-raw"] = subject

	req := validExchangeRequest()
	req.ClientID = "client-pub"
	req.ClientSecret = ""
	if _, err := s.Handle(context.Background(), req); err != nil {
		t.Errorf("Handle: %v", err)
	}
}

func TestTokenExchange_Handle_ScopeSubsetEnforced(t *testing.T) {
	s, auth, val, _ := newExchangeStrategy(t)
	auth.clients["client-A"] = confidentialExchangeClient()
	val.tokens["subject-token-raw"] = validSubjectToken()
	req := validExchangeRequest()
	req.Scopes = []string{"read", "admin"} // admin not on subject_token
	_, err := s.Handle(context.Background(), req)
	if !errors.Is(err, application.ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest", err)
	}
}

func TestTokenExchange_Handle_ScopeInheritsFromSubject(t *testing.T) {
	s, auth, val, repo := newExchangeStrategy(t)
	auth.clients["client-A"] = confidentialExchangeClient()
	val.tokens["subject-token-raw"] = validSubjectToken()
	resp, err := s.Handle(context.Background(), validExchangeRequest())
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	stored := repo.tokens["mock-token-123"]
	if stored == nil {
		t.Fatal("expected token to be persisted")
	}
	if !slices.Equal(stored.Scopes, []string{"read", "write"}) {
		t.Errorf("stored.Scopes = %v, want subject_token's scopes", stored.Scopes)
	}
	if resp.Scope != "read write" {
		t.Errorf("response scope = %q", resp.Scope)
	}
}

func TestTokenExchange_Handle_TTLCapsAtMax(t *testing.T) {
	s, auth, val, _ := newExchangeStrategy(t,
		func(c *application.TokenExchangeStrategyConfig) { c.MaxTTL = 30 * time.Second },
	)
	auth.clients["client-A"] = confidentialExchangeClient()
	val.tokens["subject-token-raw"] = validSubjectToken()
	resp, err := s.Handle(context.Background(), validExchangeRequest())
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.ExpiresIn > 30 {
		t.Errorf("ExpiresIn = %d, want ≤ 30", resp.ExpiresIn)
	}
}

func TestTokenExchange_Handle_TTLCapsAtSubjectTokenRemaining(t *testing.T) {
	s, auth, val, _ := newExchangeStrategy(t)
	auth.clients["client-A"] = confidentialExchangeClient()
	subject := validSubjectToken()
	subject.ExpiresAt = time.Now().Add(45 * time.Second) // shorter than default cap
	val.tokens["subject-token-raw"] = subject
	resp, err := s.Handle(context.Background(), validExchangeRequest())
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.ExpiresIn > 45 {
		t.Errorf("ExpiresIn = %d, want ≤ 45 (subject_token remaining)", resp.ExpiresIn)
	}
}

func TestTokenExchange_Handle_DepthCapEnforced(t *testing.T) {
	s, auth, val, _ := newExchangeStrategy(t,
		func(c *application.TokenExchangeStrategyConfig) { c.MaxDepth = 2 },
	)
	auth.clients["client-A"] = confidentialExchangeClient()
	subject := validSubjectToken()
	// Two-level subject chain + one new actor = depth 3, above the cap of 2.
	subject.Act = &domain.Actor{Sub: "actor-1", Act: &domain.Actor{Sub: "actor-2"}}
	val.tokens["subject-token-raw"] = subject

	_, err := s.Handle(context.Background(), validExchangeRequest())
	if !errors.Is(err, application.ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest (depth cap)", err)
	}
}

func TestTokenExchange_Handle_AudiencePropagatesToToken(t *testing.T) {
	s, auth, val, repo := newExchangeStrategy(t)
	auth.clients["client-A"] = confidentialExchangeClient()
	val.tokens["subject-token-raw"] = validSubjectToken()
	req := validExchangeRequest()
	req.Audience = []string{"mcp-nwsl"}
	if _, err := s.Handle(context.Background(), req); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	stored := repo.tokens["mock-token-123"]
	if stored == nil {
		t.Fatal("expected token to be persisted")
	}
	if !slices.Equal(stored.Audience, []string{"mcp-nwsl"}) {
		t.Errorf("audience = %v", stored.Audience)
	}
}
