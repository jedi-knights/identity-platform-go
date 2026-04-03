//go:build unit

package application_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// --- Manual mock for UserRepository ---
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

func (m *mockUserRepo) FindByID(id string) (*domain.User, error) {
	u, ok := m.byID[id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", id)
	}
	return u, nil
}

func (m *mockUserRepo) FindByEmail(email string) (*domain.User, error) {
	u, ok := m.byEmail[email]
	if !ok {
		return nil, fmt.Errorf("not found: %s", email)
	}
	return u, nil
}

func (m *mockUserRepo) Save(u *domain.User) error {
	m.byID[u.ID] = u
	m.byEmail[u.Email] = u
	return nil
}

func (m *mockUserRepo) Update(u *domain.User) error {
	m.byID[u.ID] = u
	m.byEmail[u.Email] = u
	return nil
}

// --- Manual mock for PasswordHasher ---
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

func TestLogin_Success(t *testing.T) {
	repo := newMockUserRepo()
	hasher := &mockHasher{}
	svc := application.NewAuthService(repo, hasher)

	user := &domain.User{
		ID:           "u1",
		Email:        "alice@example.com",
		PasswordHash: "hashed:secret",
		Name:         "Alice",
		Active:       true,
	}
	_ = repo.Save(user)

	resp, err := svc.Login(context.Background(), application.LoginRequest{
		Email:    "alice@example.com",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if resp.Email != "alice@example.com" {
		t.Errorf("unexpected email: %s", resp.Email)
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	repo := newMockUserRepo()
	hasher := &mockHasher{}
	svc := application.NewAuthService(repo, hasher)

	_, err := svc.Login(context.Background(), application.LoginRequest{
		Email:    "nobody@example.com",
		Password: "secret",
	})
	if err == nil {
		t.Fatal("expected error for unknown user")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	repo := newMockUserRepo()
	hasher := &mockHasher{}
	svc := application.NewAuthService(repo, hasher)

	user := &domain.User{
		ID:           "u2",
		Email:        "bob@example.com",
		PasswordHash: "hashed:correct",
		Name:         "Bob",
		Active:       true,
	}
	_ = repo.Save(user)

	_, err := svc.Login(context.Background(), application.LoginRequest{
		Email:    "bob@example.com",
		Password: "wrong",
	})
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestLogin_DisabledAccount(t *testing.T) {
	repo := newMockUserRepo()
	hasher := &mockHasher{}
	svc := application.NewAuthService(repo, hasher)

	user := &domain.User{
		ID:           "u3",
		Email:        "carol@example.com",
		PasswordHash: "hashed:secret",
		Name:         "Carol",
		Active:       false,
	}
	_ = repo.Save(user)

	_, err := svc.Login(context.Background(), application.LoginRequest{
		Email:    "carol@example.com",
		Password: "secret",
	})
	if err == nil {
		t.Fatal("expected error for disabled account")
	}
}

func TestRegister_Success(t *testing.T) {
	repo := newMockUserRepo()
	hasher := &mockHasher{}
	svc := application.NewAuthService(repo, hasher)

	resp, err := svc.Register(context.Background(), application.RegisterRequest{
		Email:    "dave@example.com",
		Password: "pass123",
		Name:     "Dave",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if resp.Email != "dave@example.com" {
		t.Errorf("unexpected email: %s", resp.Email)
	}
	if resp.UserID == "" {
		t.Error("expected non-empty UserID")
	}
}

func TestRegister_EmailAlreadyRegistered(t *testing.T) {
	repo := newMockUserRepo()
	hasher := &mockHasher{}
	svc := application.NewAuthService(repo, hasher)

	user := &domain.User{
		ID:           "u4",
		Email:        "eve@example.com",
		PasswordHash: "hashed:pass",
		Name:         "Eve",
		Active:       true,
	}
	_ = repo.Save(user)

	_, err := svc.Register(context.Background(), application.RegisterRequest{
		Email:    "eve@example.com",
		Password: "newpass",
		Name:     "Eve Again",
	})
	if err == nil {
		t.Fatal("expected error for duplicate email")
	}
}
