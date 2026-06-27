package application_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// Manual mock for UserRepository.
type mockUserRepo struct {
	byID    map[string]*domain.User
	byEmail map[string]*domain.User
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{
		byID:    make(map[string]*domain.User),
		byEmail: make(map[string]*domain.User),
	}
}

func (m *mockUserRepo) FindByID(_ context.Context, id string) (*domain.User, error) {
	u, ok := m.byID[id]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, fmt.Sprintf("not found: %s", id))
	}
	return u, nil
}

func (m *mockUserRepo) FindByEmail(_ context.Context, email string) (*domain.User, error) {
	u, ok := m.byEmail[email]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, fmt.Sprintf("not found: %s", email))
	}
	return u, nil
}

func (m *mockUserRepo) Save(_ context.Context, u *domain.User) error {
	m.byID[u.ID] = u
	m.byEmail[u.Email] = u
	return nil
}

func (m *mockUserRepo) Update(_ context.Context, u *domain.User) error {
	m.byID[u.ID] = u
	m.byEmail[u.Email] = u
	return nil
}

func (m *mockUserRepo) MarkEmailVerified(_ context.Context, userID string, verifiedAt time.Time) error {
	u, ok := m.byID[userID]
	if !ok {
		return apperrors.New(apperrors.ErrCodeNotFound, "user not found")
	}
	stamp := verifiedAt
	u.EmailVerifiedAt = &stamp
	u.UpdatedAt = verifiedAt
	return nil
}

// Manual mock for PasswordHasher.
type mockHasher struct{}

func (h *mockHasher) Hash(password string) (string, error) {
	return "hashed:" + password, nil
}

func (h *mockHasher) Compare(hash, password string) error {
	if hash != "hashed:"+password {
		return fmt.Errorf("password mismatch")
	}
	return nil
}

// seedUser adds a user to the repo and fails the test on error.
func seedUser(t *testing.T, repo *mockUserRepo, u *domain.User) {
	t.Helper()
	if err := repo.Save(context.Background(), u); err != nil {
		t.Fatalf("seeding user: %v", err)
	}
}

func newSvc(t *testing.T) (*application.AuthService, *mockUserRepo) {
	t.Helper()
	repo := newMockUserRepo()
	return application.NewAuthService(repo, &mockHasher{}), repo
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockUserRepo)
		req     domain.LoginRequest
		wantErr bool
	}{
		{
			name: "success",
			setup: func(repo *mockUserRepo) {
				seedUser(t, repo, &domain.User{
					ID: "u1", Email: "alice@example.com",
					PasswordHash: "hashed:secret", Name: "Alice", Active: true,
				})
			},
			req:     domain.LoginRequest{Email: "alice@example.com", Password: "secret"},
			wantErr: false,
		},
		{
			name:    "user not found",
			setup:   func(*mockUserRepo) {},
			req:     domain.LoginRequest{Email: "nobody@example.com", Password: "secret"},
			wantErr: true,
		},
		{
			name:    "missing email",
			setup:   func(*mockUserRepo) {},
			req:     domain.LoginRequest{Email: "", Password: "secret"},
			wantErr: true,
		},
		{
			name:    "missing password",
			setup:   func(*mockUserRepo) {},
			req:     domain.LoginRequest{Email: "a@b.com", Password: ""},
			wantErr: true,
		},
		{
			name: "wrong password",
			setup: func(repo *mockUserRepo) {
				seedUser(t, repo, &domain.User{
					ID: "u2", Email: "bob@example.com",
					PasswordHash: "hashed:correct", Name: "Bob", Active: true,
				})
			},
			req:     domain.LoginRequest{Email: "bob@example.com", Password: "wrong"},
			wantErr: true,
		},
		{
			name: "disabled account",
			setup: func(repo *mockUserRepo) {
				seedUser(t, repo, &domain.User{
					ID: "u3", Email: "carol@example.com",
					PasswordHash: "hashed:secret", Name: "Carol", Active: false,
				})
			},
			req:     domain.LoginRequest{Email: "carol@example.com", Password: "secret"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, repo := newSvc(t)
			tt.setup(repo)
			resp, err := svc.Login(context.Background(), tt.req)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Email != tt.req.Email {
				t.Errorf("email: got %q, want %q", resp.Email, tt.req.Email)
			}
		})
	}
}

func TestRegister(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockUserRepo)
		req     domain.RegisterRequest
		wantErr bool
	}{
		{
			name:    "success",
			setup:   func(*mockUserRepo) {},
			req:     domain.RegisterRequest{Email: "dave@example.com", Password: "pass123", Name: "Dave"},
			wantErr: false,
		},
		{
			name: "email already registered",
			setup: func(repo *mockUserRepo) {
				seedUser(t, repo, &domain.User{
					ID: "u4", Email: "eve@example.com",
					PasswordHash: "hashed:pass", Name: "Eve", Active: true,
				})
			},
			req:     domain.RegisterRequest{Email: "eve@example.com", Password: "newpass", Name: "Eve Again"},
			wantErr: true,
		},
		{
			name:    "missing email",
			setup:   func(*mockUserRepo) {},
			req:     domain.RegisterRequest{Email: "", Password: "pass", Name: "Name"},
			wantErr: true,
		},
		{
			name:    "missing password",
			setup:   func(*mockUserRepo) {},
			req:     domain.RegisterRequest{Email: "a@b.com", Password: "", Name: "Name"},
			wantErr: true,
		},
		{
			name:    "missing name",
			setup:   func(*mockUserRepo) {},
			req:     domain.RegisterRequest{Email: "a@b.com", Password: "pass", Name: ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, repo := newSvc(t)
			tt.setup(repo)
			resp, err := svc.Register(context.Background(), tt.req)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Email != tt.req.Email {
				t.Errorf("email: got %q, want %q", resp.Email, tt.req.Email)
			}
			if resp.UserID == "" {
				t.Error("expected non-empty UserID")
			}
		})
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

func TestLogin_EmitsUserAuthenticated(t *testing.T) {
	repo := newMockUserRepo()
	hasher := &mockHasher{}
	seedUser(t, repo, &domain.User{
		ID:           "u-1",
		Email:        "test@example.com",
		PasswordHash: "hashed:pw",
		Name:         "Test",
		Active:       true,
	})
	sink := &captureSink{}
	svc := application.NewAuthService(repo, hasher).WithAudit(audit.New(sink), "identity-service")

	if _, err := svc.Login(context.Background(), domain.LoginRequest{
		Email:    "test@example.com",
		Password: "pw",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	assertUserAuthenticatedEvent(t, sink.events[0])
}

// assertUserAuthenticatedEvent verifies every field on a
// user_authenticated event. Extracted from
// TestLogin_EmitsUserAuthenticated so the flat list of independent
// assertions does not push the test's cyclomatic complexity past the
// gocyclo budget.
func assertUserAuthenticatedEvent(t *testing.T, e audit.Event) {
	t.Helper()
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"EventType", e.EventType, "user_authenticated"},
		{"Service", e.Service, "identity-service"},
		{"ActorType", string(e.ActorType), string(audit.ActorTypeUser)},
		{"ActorID", e.ActorID, "u-1"},
		{"SubjectID", e.SubjectID, "u-1"},
		{"ResourceKind", string(e.ResourceKind), string(audit.ResourceKindEndpoint)},
		{"ResourcePath", e.ResourcePath, "identity-service/endpoint/authenticate"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("event.%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	if email, _ := e.Attrs["email"].(string); email != "test@example.com" {
		t.Errorf("attrs.email = %v, want test@example.com", e.Attrs["email"])
	}
}

func TestLogin_AuditFailureSurfaces(t *testing.T) {
	repo := newMockUserRepo()
	hasher := &mockHasher{}
	seedUser(t, repo, &domain.User{
		ID:           "u-1",
		Email:        "test@example.com",
		PasswordHash: "hashed:pw",
		Name:         "Test",
		Active:       true,
	})
	sink := &captureSink{err: errAuditFailure}
	svc := application.NewAuthService(repo, hasher).WithAudit(audit.New(sink), "identity-service")

	_, err := svc.Login(context.Background(), domain.LoginRequest{
		Email:    "test@example.com",
		Password: "pw",
	})
	if err == nil {
		t.Fatal("expected error when audit emit fails")
	}
	if !errors.Is(err, errAuditFailure) {
		t.Errorf("expected wrapped audit error, got %v", err)
	}
}

func TestRegister_EmitsUserRegistered(t *testing.T) {
	repo := newMockUserRepo()
	hasher := &mockHasher{}
	sink := &captureSink{}
	svc := application.NewAuthService(repo, hasher).WithAudit(audit.New(sink), "identity-service")

	resp, err := svc.Register(context.Background(), domain.RegisterRequest{
		Email:    "new@example.com",
		Password: "pw",
		Name:     "New User",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	e := sink.events[0]
	if e.EventType != "user_registered" {
		t.Errorf("event_type = %q, want user_registered", e.EventType)
	}
	if e.ActorID != resp.UserID {
		t.Errorf("actor_id = %q, want %q", e.ActorID, resp.UserID)
	}
	if e.SubjectID != resp.UserID {
		t.Errorf("subject_id = %q, want %q", e.SubjectID, resp.UserID)
	}
	if e.ResourcePath != "identity-service/endpoint/register" {
		t.Errorf("resource_path = %q, want identity-service/endpoint/register", e.ResourcePath)
	}
}

func TestRegister_AuditFailureSurfaces(t *testing.T) {
	repo := newMockUserRepo()
	hasher := &mockHasher{}
	sink := &captureSink{err: errAuditFailure}
	svc := application.NewAuthService(repo, hasher).WithAudit(audit.New(sink), "identity-service")

	_, err := svc.Register(context.Background(), domain.RegisterRequest{
		Email:    "new@example.com",
		Password: "pw",
		Name:     "New User",
	})
	if err == nil {
		t.Fatal("expected error when audit emit fails")
	}
	if !errors.Is(err, errAuditFailure) {
		t.Errorf("expected wrapped audit error, got %v", err)
	}
}

func TestAuthService_WithAudit_NilEmitterPanics(t *testing.T) {
	repo := newMockUserRepo()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = application.NewAuthService(repo, &mockHasher{}).WithAudit(nil, "identity-service")
}
