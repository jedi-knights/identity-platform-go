package application_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// stubCodeRepo serves a single canned code on Consume; after the first
// consume it returns ErrAuthorizationCodeNotFound. Save records calls for
// inspection.
type stubCodeRepo struct {
	mu       sync.Mutex
	code     *domain.AuthorizationCode
	consumed bool
}

func (r *stubCodeRepo) Save(_ context.Context, code *domain.AuthorizationCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.code = code
	r.consumed = false
	return nil
}

func (r *stubCodeRepo) Consume(_ context.Context, raw string) (*domain.AuthorizationCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.code == nil || r.code.Code != raw || r.consumed {
		return nil, domain.ErrAuthorizationCodeNotFound
	}
	r.consumed = true
	return r.code, nil
}

// s256 computes the base64url-no-padding SHA-256 hash of v — what a real
// PKCE client would store as code_challenge given a particular verifier.
func s256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

const (
	testVerifier = "verifier-43-chars-or-more-rfc7636-section-4-1-1"
	testCode     = "test-code-abcdef"
	testRedirect = "https://rp.example.com/cb"
)

// authCodeFixtures stamps a complete strategy + repos + client for use in
// happy-path and per-failure tests. Tests that need to mutate one input
// take the returned struct and reassign the relevant field on req before
// calling Handle.
type authCodeFixtures struct {
	strategy         *application.AuthorizationCodeStrategy
	clientAuth       *mockClientAuthenticator
	codeRepo         *stubCodeRepo
	tokenRepo        *mockTokenRepo
	refreshTokenRepo *mockRefreshTokenRepo
	req              domain.GrantRequest
}

func newAuthCodeFixtures(t *testing.T) *authCodeFixtures {
	t.Helper()
	clientAuth := newMockClientAuthenticator()
	clientAuth.clients["client-conf"] = &domain.Client{
		ID:           "client-conf",
		Secret:       "secret-123",
		Type:         domain.ClientTypeConfidential,
		Scopes:       []string{"openid", "email", "read"},
		RedirectURIs: []string{testRedirect},
		GrantTypes:   []domain.GrantType{domain.GrantTypeAuthorizationCode},
	}
	codeRepo := &stubCodeRepo{}
	if err := codeRepo.Save(context.Background(), &domain.AuthorizationCode{
		Code:                testCode,
		ClientID:            "client-conf",
		Subject:             "user-1",
		RedirectURI:         testRedirect,
		Scopes:              []string{"openid", "email"},
		CodeChallenge:       s256(testVerifier),
		CodeChallengeMethod: "S256",
		IssuedAt:            time.Now(),
		ExpiresAt:           time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("seed Save: %v", err)
	}
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	strategy := application.NewAuthorizationCodeStrategy(
		clientAuth, codeRepo, tokenRepo, refreshTokenRepo, &mockTokenGen{}, nil, nil, nil, time.Hour, 7*24*time.Hour, 5*time.Minute, nil,
	)
	return &authCodeFixtures{
		strategy:         strategy,
		clientAuth:       clientAuth,
		codeRepo:         codeRepo,
		tokenRepo:        tokenRepo,
		refreshTokenRepo: refreshTokenRepo,
		req: domain.GrantRequest{
			GrantType:    domain.GrantTypeAuthorizationCode,
			ClientID:     "client-conf",
			ClientSecret: "secret-123",
			Code:         testCode,
			CodeVerifier: testVerifier,
			RedirectURI:  testRedirect,
		},
	}
}

func TestAuthorizationCodeStrategy_Handle_HappyPath(t *testing.T) {
	// Arrange
	f := newAuthCodeFixtures(t)

	// Act
	resp, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("AccessToken is empty")
	}
	if resp.RefreshToken == "" {
		t.Error("RefreshToken is empty")
	}
	if len(f.tokenRepo.tokens) != 1 {
		t.Errorf("got %d tokens saved, want 1", len(f.tokenRepo.tokens))
	}
}

func TestAuthorizationCodeStrategy_Handle_EmbedsAuthorizationDetailsOnToken(t *testing.T) {
	// ADR-0017: granted-details persisted on the AuthorizationCode at
	// /oauth/authorize must land on the access token at /oauth/token
	// so RAR-aware resource servers (jk-mcp-nwsl, jk-mcp-ecnl) can
	// enforce the per-call permissions the user originally approved.
	f := newAuthCodeFixtures(t)
	// Reseed the code with AuthorizationDetails — the default fixture
	// omits them, so explicitly install them and overwrite the existing
	// seeded code under the same Code value.
	if err := f.codeRepo.Save(context.Background(), &domain.AuthorizationCode{
		Code:                testCode,
		ClientID:            "client-conf",
		Subject:             "user-1",
		RedirectURI:         testRedirect,
		Scopes:              []string{"openid", "email"},
		CodeChallenge:       s256(testVerifier),
		CodeChallengeMethod: "S256",
		AuthorizationDetails: []domain.AuthorizationDetail{
			{Type: domain.AuthorizationDetailTypeMCPTool, Raw: []byte(`{"type":"mcp_tool","tool":"get_standings"}`)},
		},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("seed Save: %v", err)
	}

	if _, err := f.strategy.Handle(context.Background(), f.req); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if len(f.tokenRepo.tokens) != 1 {
		t.Fatalf("got %d tokens saved, want 1", len(f.tokenRepo.tokens))
	}
	var saved *domain.Token
	for _, tok := range f.tokenRepo.tokens {
		saved = tok
	}
	if len(saved.AuthorizationDetails) != 1 {
		t.Fatalf("Token.AuthorizationDetails len = %d, want 1", len(saved.AuthorizationDetails))
	}
	if saved.AuthorizationDetails[0].Type != domain.AuthorizationDetailTypeMCPTool {
		t.Errorf("Type = %q, want mcp_tool", saved.AuthorizationDetails[0].Type)
	}
}

// TestAuthorizationCodeStrategy_Handle_StampsAcrValuePassword covers
// ADR-0024 — every authorization_code redemption re-authenticates the
// user from scratch via login-ui's one authentication method, so the
// issued token always carries domain.AcrValuePassword.
func TestAuthorizationCodeStrategy_Handle_StampsAcrValuePassword(t *testing.T) {
	f := newAuthCodeFixtures(t)

	if _, err := f.strategy.Handle(context.Background(), f.req); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	var saved *domain.Token
	for _, tok := range f.tokenRepo.tokens {
		saved = tok
	}
	if saved == nil {
		t.Fatal("expected a token to be saved")
	}
	if saved.Acr != domain.AcrValuePassword {
		t.Errorf("Acr = %q, want %q", saved.Acr, domain.AcrValuePassword)
	}
}

func TestAuthorizationCodeStrategy_Handle_MissingCode_InvalidRequest(t *testing.T) {
	// Arrange
	f := newAuthCodeFixtures(t)
	f.req.Code = ""

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if !errors.Is(err, application.ErrInvalidRequest) {
		t.Errorf("err = %v, want wrapping ErrInvalidRequest", err)
	}
}

func TestAuthorizationCodeStrategy_Handle_MissingRedirectURI_InvalidRequest(t *testing.T) {
	// Arrange
	f := newAuthCodeFixtures(t)
	f.req.RedirectURI = ""

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if !errors.Is(err, application.ErrInvalidRequest) {
		t.Errorf("err = %v, want wrapping ErrInvalidRequest", err)
	}
}

func TestAuthorizationCodeStrategy_Handle_MissingCodeVerifier_InvalidRequest(t *testing.T) {
	// Arrange — PKCE is mandatory (ADR-0009).
	f := newAuthCodeFixtures(t)
	f.req.CodeVerifier = ""

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if !errors.Is(err, application.ErrInvalidRequest) {
		t.Errorf("err = %v, want wrapping ErrInvalidRequest", err)
	}
}

func TestAuthorizationCodeStrategy_Handle_WrongClientSecret_InvalidClient(t *testing.T) {
	// Arrange — confidential client with wrong secret; clientAuth returns
	// an apperrors.ErrCodeUnauthorized which the handler maps to
	// invalid_client. The strategy must propagate that without wrapping
	// it in ErrInvalidGrant.
	f := newAuthCodeFixtures(t)
	f.req.ClientSecret = "wrong-secret"

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if err == nil {
		t.Fatal("expected error for wrong client secret")
	}
	// The exact mapping is the handler's concern; the strategy just needs to
	// NOT swallow the auth failure. Re-check by confirming the error is not
	// ErrInvalidGrant (which would mean we crossed the wrong wire).
	if errors.Is(err, application.ErrInvalidGrant) {
		t.Errorf("err = %v incorrectly classified as invalid_grant", err)
	}
}

func TestAuthorizationCodeStrategy_Handle_ClientLacksGrantType_UnauthorizedClient(t *testing.T) {
	// Arrange — strip the grant type from the seeded client.
	f := newAuthCodeFixtures(t)
	f.clientAuth.clients["client-conf"].GrantTypes = []domain.GrantType{domain.GrantTypeClientCredentials}

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if !errors.Is(err, application.ErrUnauthorizedClient) {
		t.Errorf("err = %v, want wrapping ErrUnauthorizedClient", err)
	}
}

func TestAuthorizationCodeStrategy_Handle_UnknownCode_InvalidGrant(t *testing.T) {
	// Arrange
	f := newAuthCodeFixtures(t)
	f.req.Code = "no-such-code"

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if !errors.Is(err, application.ErrInvalidGrant) {
		t.Errorf("err = %v, want wrapping ErrInvalidGrant", err)
	}
}

func TestAuthorizationCodeStrategy_Handle_ReplayedCode_InvalidGrant(t *testing.T) {
	// Arrange — first call consumes; second call must fail invalid_grant.
	f := newAuthCodeFixtures(t)
	if _, err := f.strategy.Handle(context.Background(), f.req); err != nil {
		t.Fatalf("first Handle: %v", err)
	}

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if !errors.Is(err, application.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant on replayed code", err)
	}
}

func TestAuthorizationCodeStrategy_Handle_WrongClientForCode_InvalidGrant(t *testing.T) {
	// Arrange — register a second client that uses the right secret but
	// did not originate the code.
	f := newAuthCodeFixtures(t)
	f.clientAuth.clients["client-other"] = &domain.Client{
		ID:         "client-other",
		Secret:     "other-secret",
		Type:       domain.ClientTypeConfidential,
		GrantTypes: []domain.GrantType{domain.GrantTypeAuthorizationCode},
	}
	f.req.ClientID = "client-other"
	f.req.ClientSecret = "other-secret"

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if !errors.Is(err, application.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant when client_id doesn't match code", err)
	}
}

func TestAuthorizationCodeStrategy_Handle_WrongRedirectURI_InvalidGrant(t *testing.T) {
	// Arrange
	f := newAuthCodeFixtures(t)
	f.clientAuth.clients["client-conf"].RedirectURIs = append(
		f.clientAuth.clients["client-conf"].RedirectURIs,
		"https://rp.example.com/other-cb",
	)
	f.req.RedirectURI = "https://rp.example.com/other-cb"

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if !errors.Is(err, application.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant when redirect_uri mismatches code", err)
	}
}

func TestAuthorizationCodeStrategy_Handle_NonS256Method_InvalidGrant(t *testing.T) {
	// Arrange — defensive check: even if a "plain" code somehow ended up
	// in the store, the strategy must refuse to honour it.
	f := newAuthCodeFixtures(t)
	f.codeRepo.code.CodeChallengeMethod = "plain"

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if !errors.Is(err, application.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant for non-S256 method", err)
	}
}

func TestAuthorizationCodeStrategy_Handle_WrongVerifier_InvalidGrant(t *testing.T) {
	// Arrange
	f := newAuthCodeFixtures(t)
	f.req.CodeVerifier = "attacker-guess-that-doesnt-match-the-challenge"

	// Act
	_, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if !errors.Is(err, application.ErrInvalidGrant) {
		t.Errorf("err = %v, want ErrInvalidGrant for wrong code_verifier", err)
	}
}

func TestAuthorizationCodeStrategy_Handle_PublicClientNoSecretAccepted(t *testing.T) {
	// Arrange — public client (no secret) presents an empty secret. The
	// seeded code is updated to belong to this client; the secret store
	// also has empty Secret so the constant-time compare passes.
	f := newAuthCodeFixtures(t)
	f.clientAuth.clients["client-pub"] = &domain.Client{
		ID:           "client-pub",
		Secret:       "",
		Type:         domain.ClientTypePublic,
		Scopes:       []string{"openid"},
		RedirectURIs: []string{testRedirect},
		GrantTypes:   []domain.GrantType{domain.GrantTypeAuthorizationCode},
	}
	f.codeRepo.code.ClientID = "client-pub"
	f.req.ClientID = "client-pub"
	f.req.ClientSecret = ""

	// Act
	resp, err := f.strategy.Handle(context.Background(), f.req)

	// Assert
	if err != nil {
		t.Fatalf("public client should be accepted with empty secret, got: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("public client AccessToken is empty")
	}
}
