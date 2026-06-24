package application_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// fakeAuthCodeRepo is a minimal AuthorizationCodeRepository for issuer tests.
// Records every Save call so tests can inspect what was persisted.
type fakeAuthCodeRepo struct {
	mu    sync.Mutex
	saves []*domain.AuthorizationCode
	err   error
}

func (r *fakeAuthCodeRepo) Save(_ context.Context, code *domain.AuthorizationCode) error {
	if r.err != nil {
		return r.err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.saves = append(r.saves, code)
	return nil
}

func (r *fakeAuthCodeRepo) Consume(context.Context, string) (*domain.AuthorizationCode, error) {
	return nil, domain.ErrAuthorizationCodeNotFound
}

func (r *fakeAuthCodeRepo) saved() []*domain.AuthorizationCode {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.AuthorizationCode, len(r.saves))
	copy(out, r.saves)
	return out
}

func validIssueReq() ports.IssueCodeRequest {
	return ports.IssueCodeRequest{
		ClientID:            "client-a",
		Subject:             "user-1",
		RedirectURI:         "https://rp.example.com/cb",
		Scopes:              []string{"openid", "email"},
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}
}

func TestAuthorizationCodeIssuer_Issue_PersistsCode(t *testing.T) {
	// Arrange
	repo := &fakeAuthCodeRepo{}
	issuer := application.NewAuthorizationCodeIssuer(repo, 60*time.Second)

	// Act
	raw, err := issuer.Issue(context.Background(), validIssueReq())

	// Assert
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if raw == "" {
		t.Fatal("Issue returned empty code")
	}
	saved := repo.saved()
	if len(saved) != 1 {
		t.Fatalf("got %d saved codes, want 1", len(saved))
	}
	if saved[0].Code != raw {
		t.Errorf("saved Code = %q, returned %q", saved[0].Code, raw)
	}
}

func TestAuthorizationCodeIssuer_Issue_CodeIs64HexChars(t *testing.T) {
	// Arrange — 32 bytes of CSPRNG entropy hex-encoded = 64 chars (ADR-0009).
	repo := &fakeAuthCodeRepo{}
	issuer := application.NewAuthorizationCodeIssuer(repo, time.Minute)

	// Act
	raw, err := issuer.Issue(context.Background(), validIssueReq())

	// Assert
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(raw) != 64 {
		t.Errorf("code length = %d, want 64", len(raw))
	}
	for _, c := range raw {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			t.Errorf("code contains non-hex char %q", c)
			break
		}
	}
}

func TestAuthorizationCodeIssuer_Issue_RejectsNonS256Method(t *testing.T) {
	// Arrange — plain PKCE is universally rejected. Trying other documented
	// values too, plus the empty case, since the issuer is the last barrier
	// before the wrong value reaches the store.
	repo := &fakeAuthCodeRepo{}
	issuer := application.NewAuthorizationCodeIssuer(repo, time.Minute)
	for _, method := range []string{"plain", "", "S192", "SHA256"} {
		t.Run("method="+method, func(t *testing.T) {
			req := validIssueReq()
			req.CodeChallengeMethod = method

			// Act
			_, err := issuer.Issue(context.Background(), req)

			// Assert
			if err == nil {
				t.Fatalf("Issue accepted method %q, want error", method)
			}
		})
	}
}

func TestAuthorizationCodeIssuer_Issue_RequiresClientID(t *testing.T) {
	// Arrange
	repo := &fakeAuthCodeRepo{}
	issuer := application.NewAuthorizationCodeIssuer(repo, time.Minute)
	req := validIssueReq()
	req.ClientID = ""

	// Act
	_, err := issuer.Issue(context.Background(), req)

	// Assert
	if err == nil {
		t.Fatal("expected error for empty ClientID, got nil")
	}
}

func TestAuthorizationCodeIssuer_Issue_RequiresSubject(t *testing.T) {
	// Arrange
	repo := &fakeAuthCodeRepo{}
	issuer := application.NewAuthorizationCodeIssuer(repo, time.Minute)
	req := validIssueReq()
	req.Subject = ""

	// Act
	_, err := issuer.Issue(context.Background(), req)

	// Assert
	if err == nil {
		t.Fatal("expected error for empty Subject, got nil")
	}
}

func TestAuthorizationCodeIssuer_Issue_RequiresRedirectURI(t *testing.T) {
	// Arrange
	repo := &fakeAuthCodeRepo{}
	issuer := application.NewAuthorizationCodeIssuer(repo, time.Minute)
	req := validIssueReq()
	req.RedirectURI = ""

	// Act
	_, err := issuer.Issue(context.Background(), req)

	// Assert
	if err == nil {
		t.Fatal("expected error for empty RedirectURI, got nil")
	}
}

func TestAuthorizationCodeIssuer_Issue_StampsTTL(t *testing.T) {
	// Arrange — ExpiresAt should equal IssuedAt + ttl within a small slop.
	repo := &fakeAuthCodeRepo{}
	const ttl = 45 * time.Second
	issuer := application.NewAuthorizationCodeIssuer(repo, ttl)

	// Act
	if _, err := issuer.Issue(context.Background(), validIssueReq()); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Assert
	saved := repo.saved()[0]
	delta := saved.ExpiresAt.Sub(saved.IssuedAt)
	if delta != ttl {
		t.Errorf("ExpiresAt - IssuedAt = %v, want %v", delta, ttl)
	}
}

func TestAuthorizationCodeIssuer_Issue_CopiesAllRequestFields(t *testing.T) {
	// Arrange
	repo := &fakeAuthCodeRepo{}
	issuer := application.NewAuthorizationCodeIssuer(repo, time.Minute)
	req := validIssueReq()
	req.Nonce = "nonce-abc"

	// Act
	if _, err := issuer.Issue(context.Background(), req); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Assert
	saved := repo.saved()[0]
	checks := []struct {
		name string
		got  any
		want any
	}{
		{"ClientID", saved.ClientID, req.ClientID},
		{"Subject", saved.Subject, req.Subject},
		{"RedirectURI", saved.RedirectURI, req.RedirectURI},
		{"CodeChallenge", saved.CodeChallenge, req.CodeChallenge},
		{"CodeChallengeMethod", saved.CodeChallengeMethod, req.CodeChallengeMethod},
		{"Nonce", saved.Nonce, req.Nonce},
		{"Scopes joined", strings.Join(saved.Scopes, ","), strings.Join(req.Scopes, ",")},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestAuthorizationCodeIssuer_Issue_RepoErrorPropagates(t *testing.T) {
	// Arrange
	wantErr := errors.New("disk on fire")
	repo := &fakeAuthCodeRepo{err: wantErr}
	issuer := application.NewAuthorizationCodeIssuer(repo, time.Minute)

	// Act
	_, err := issuer.Issue(context.Background(), validIssueReq())

	// Assert
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want wrapping %v", err, wantErr)
	}
}
