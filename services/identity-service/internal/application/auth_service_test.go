package application_test

import (
	"context"
	"fmt"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
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
