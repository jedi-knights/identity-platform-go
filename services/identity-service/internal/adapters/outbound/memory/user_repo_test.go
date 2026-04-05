package memory_test

import (
	"context"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

func newUser(t *testing.T, id, email, name string) *domain.User {
	t.Helper()
	return &domain.User{ID: id, Email: email, Name: name, Active: true}
}

// --- aliasing tests ---

func TestUserRepository_FindByID_NoAliasing(t *testing.T) {
	repo := memory.NewUserRepository()
	user := newUser(t, "u1", "a@example.com", "Alice")
	if err := repo.Save(context.Background(), user); err != nil {
		t.Fatal(err)
	}

	got, err := repo.FindByID(context.Background(), "u1")
	if err != nil {
		t.Fatal(err)
	}

	// Mutating the returned pointer must not affect stored state.
	got.Name = "Mutated"

	got2, err := repo.FindByID(context.Background(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if got2.Name != "Alice" {
		t.Errorf("aliasing: stored name changed to %q after caller mutation", got2.Name)
	}
}

func TestUserRepository_Save_NoAliasing(t *testing.T) {
	repo := memory.NewUserRepository()
	user := newUser(t, "u2", "b@example.com", "Bob")
	if err := repo.Save(context.Background(), user); err != nil {
		t.Fatal(err)
	}

	// Mutating the original pointer after Save must not affect stored state.
	user.Name = "Mutated"

	got, err := repo.FindByID(context.Background(), "u2")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Bob" {
		t.Errorf("aliasing: stored name changed to %q after caller mutation", got.Name)
	}
}

func TestUserRepository_FindByEmail_NoAliasing(t *testing.T) {
	repo := memory.NewUserRepository()
	user := newUser(t, "u3", "c@example.com", "Carol")
	if err := repo.Save(context.Background(), user); err != nil {
		t.Fatal(err)
	}

	got, err := repo.FindByEmail(context.Background(), "c@example.com")
	if err != nil {
		t.Fatal(err)
	}

	got.Name = "Mutated"

	got2, err := repo.FindByEmail(context.Background(), "c@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got2.Name != "Carol" {
		t.Errorf("aliasing: stored name changed to %q after caller mutation", got2.Name)
	}
}

func TestUserRepository_Update_NoAliasing(t *testing.T) {
	repo := memory.NewUserRepository()
	user := newUser(t, "u4", "d@example.com", "Dave")
	if err := repo.Save(context.Background(), user); err != nil {
		t.Fatal(err)
	}

	updated := &domain.User{ID: "u4", Email: "d@example.com", Name: "Dave Updated", Active: true}
	if err := repo.Update(context.Background(), updated); err != nil {
		t.Fatal(err)
	}

	// Mutating the pointer passed to Update must not affect stored state.
	updated.Name = "Mutated"

	got, err := repo.FindByID(context.Background(), "u4")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Dave Updated" {
		t.Errorf("aliasing: stored name changed to %q after caller mutation", got.Name)
	}
}

// --- error-path contract tests ---

func TestUserRepository_FindByID_NotFound(t *testing.T) {
	repo := memory.NewUserRepository()
	_, err := repo.FindByID(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing ID, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got: %v", err)
	}
}

func TestUserRepository_FindByEmail_NotFound(t *testing.T) {
	repo := memory.NewUserRepository()
	_, err := repo.FindByEmail(context.Background(), "nobody@example.com")
	if err == nil {
		t.Fatal("expected error for missing email, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got: %v", err)
	}
}

func TestUserRepository_Save_DuplicateEmail_ReturnsConflict(t *testing.T) {
	repo := memory.NewUserRepository()
	first := newUser(t, "u5", "e@example.com", "Eve")
	if err := repo.Save(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := newUser(t, "u6", "e@example.com", "Eve2") // same email
	err := repo.Save(context.Background(), second)
	if err == nil {
		t.Fatal("expected conflict error for duplicate email, got nil")
	}
	if !apperrors.IsConflict(err) {
		t.Errorf("expected ErrCodeConflict, got: %v", err)
	}
}

func TestUserRepository_Update_NotFound(t *testing.T) {
	repo := memory.NewUserRepository()
	ghost := newUser(t, "ghost", "ghost@example.com", "Ghost")
	err := repo.Update(context.Background(), ghost)
	if err == nil {
		t.Fatal("expected error for missing ID, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got: %v", err)
	}
}

// TestUserRepository_Update_EmailChange verifies that updating a user's email
// correctly re-indexes: the old email no longer resolves, and the new one does.
func TestUserRepository_Update_EmailChange(t *testing.T) {
	repo := memory.NewUserRepository()
	user := newUser(t, "u7", "old@example.com", "Frank")
	if err := repo.Save(context.Background(), user); err != nil {
		t.Fatal(err)
	}

	updated := &domain.User{ID: "u7", Email: "new@example.com", Name: "Frank", Active: true}
	if err := repo.Update(context.Background(), updated); err != nil {
		t.Fatal(err)
	}

	// Old email must no longer resolve.
	if _, err := repo.FindByEmail(context.Background(), "old@example.com"); !apperrors.IsNotFound(err) {
		t.Errorf("old email still resolves after update; want ErrCodeNotFound, got: %v", err)
	}

	// New email must resolve to the updated user.
	got, err := repo.FindByEmail(context.Background(), "new@example.com")
	if err != nil {
		t.Fatalf("FindByEmail new: %v", err)
	}
	if got.Email != "new@example.com" {
		t.Errorf("email: got %q, want %q", got.Email, "new@example.com")
	}
}
