//go:build integration

package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/postgres"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// testDatabaseURL returns the database URL for integration tests or skips the
// test when TEST_DATABASE_URL is not set. This keeps the test suite runnable
// in environments without a real database (unit CI, local dev without Docker).
func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	return url
}

// setupRepo applies migrations, opens a pool, and returns the repo plus the
// pool so tests can execute cleanup SQL directly.
func setupRepo(t *testing.T) (*postgres.UserRepository, *pgxpool.Pool) {
	t.Helper()
	dbURL := testDatabaseURL(t)

	if err := postgres.RunMigrations(dbURL); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	ctx := context.Background()
	pool, err := postgres.Connect(ctx, dbURL)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	return postgres.NewUserRepository(pool), pool
}

// deleteUser removes a user by ID for test cleanup; errors are ignored so a
// missing row (or a test that never inserted) does not fail the cleanup path.
func deleteUser(t *testing.T, pool *pgxpool.Pool, id string) {
	t.Helper()
	_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
}

func newTestUser(t *testing.T, suffix string) *domain.User {
	t.Helper()
	return &domain.User{
		ID:           "test-id-" + suffix,
		Email:        "user-" + suffix + "@example.com",
		Name:         "Test User " + suffix,
		PasswordHash: "$2a$10$hashedpassword" + suffix,
		Active:       true,
		CreatedAt:    time.Now().UTC().Truncate(time.Second),
		UpdatedAt:    time.Now().UTC().Truncate(time.Second),
	}
}

// TestSaveAndFindByID verifies the basic round-trip: Save a user, then retrieve
// it by ID and confirm every field round-trips correctly.
func TestSaveAndFindByID(t *testing.T) {
	repo, pool := setupRepo(t)
	ctx := context.Background()

	user := newTestUser(t, "save-findbyid")
	t.Cleanup(func() { deleteUser(t, pool, user.ID) })

	if err := repo.Save(ctx, user); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}

	if got.ID != user.ID {
		t.Errorf("ID: got %q, want %q", got.ID, user.ID)
	}
	if got.Email != user.Email {
		t.Errorf("Email: got %q, want %q", got.Email, user.Email)
	}
	if got.Name != user.Name {
		t.Errorf("Name: got %q, want %q", got.Name, user.Name)
	}
	if got.PasswordHash != user.PasswordHash {
		t.Errorf("PasswordHash: got %q, want %q", got.PasswordHash, user.PasswordHash)
	}
	if got.Active != user.Active {
		t.Errorf("Active: got %v, want %v", got.Active, user.Active)
	}
}

// TestFindByEmail verifies that a saved user can be retrieved by email address.
func TestFindByEmail(t *testing.T) {
	repo, pool := setupRepo(t)
	ctx := context.Background()

	user := newTestUser(t, "findbyemail")
	t.Cleanup(func() { deleteUser(t, pool, user.ID) })

	if err := repo.Save(ctx, user); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindByEmail(ctx, user.Email)
	if err != nil {
		t.Fatalf("FindByEmail: %v", err)
	}

	if got.ID != user.ID {
		t.Errorf("ID: got %q, want %q", got.ID, user.ID)
	}
	if got.Email != user.Email {
		t.Errorf("Email: got %q, want %q", got.Email, user.Email)
	}
}

// TestSaveDuplicateEmailConflict verifies that saving two users with the same
// email returns an ErrCodeConflict — matching the memory adapter's behaviour.
func TestSaveDuplicateEmailConflict(t *testing.T) {
	repo, pool := setupRepo(t)
	ctx := context.Background()

	first := newTestUser(t, "dup-email-1")
	first.Email = "duplicate-inttest@example.com"
	t.Cleanup(func() { deleteUser(t, pool, first.ID) })

	second := newTestUser(t, "dup-email-2")
	second.Email = "duplicate-inttest@example.com" // intentional duplicate

	if err := repo.Save(ctx, first); err != nil {
		t.Fatalf("Save first: %v", err)
	}

	err := repo.Save(ctx, second)
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}
	if !apperrors.IsConflict(err) {
		t.Errorf("expected ErrCodeConflict, got: %v", err)
	}
}

// TestUpdate verifies that Update persists changed fields and that FindByID
// returns the updated values.
func TestUpdate(t *testing.T) {
	repo, pool := setupRepo(t)
	ctx := context.Background()

	user := newTestUser(t, "update")
	t.Cleanup(func() { deleteUser(t, pool, user.ID) })

	if err := repo.Save(ctx, user); err != nil {
		t.Fatalf("Save: %v", err)
	}

	user.Name = "Updated Name"
	user.Active = false

	if err := repo.Update(ctx, user); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindByID after update: %v", err)
	}

	if got.Name != "Updated Name" {
		t.Errorf("Name: got %q, want %q", got.Name, "Updated Name")
	}
	if got.Active != false {
		t.Errorf("Active: got %v, want false", got.Active)
	}
}

// TestUpdate_DuplicateEmail_ReturnsConflict verifies that changing a user's email to
// one already taken returns ErrCodeConflict, matching the memory adapter's behaviour.
func TestUpdate_DuplicateEmail_ReturnsConflict(t *testing.T) {
	repo, pool := setupRepo(t)
	ctx := context.Background()

	first := newTestUser(t, "dup-update-1")
	second := newTestUser(t, "dup-update-2")
	t.Cleanup(func() {
		deleteUser(t, pool, first.ID)
		deleteUser(t, pool, second.ID)
	})

	if err := repo.Save(ctx, first); err != nil {
		t.Fatalf("Save first: %v", err)
	}
	if err := repo.Save(ctx, second); err != nil {
		t.Fatalf("Save second: %v", err)
	}

	// Attempt to change second's email to first's email — must produce ErrCodeConflict.
	second.Email = first.Email
	err := repo.Update(ctx, second)
	if err == nil {
		t.Fatal("expected conflict error for duplicate email on update, got nil")
	}
	if !apperrors.IsConflict(err) {
		t.Errorf("expected ErrCodeConflict, got: %v", err)
	}
}

// TestUpdateNotFound verifies that updating a non-existent user returns ErrCodeNotFound.
func TestUpdateNotFound(t *testing.T) {
	repo, _ := setupRepo(t)
	ctx := context.Background()

	ghost := newTestUser(t, "ghost-update")

	err := repo.Update(ctx, ghost)
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got: %v", err)
	}
}

// TestFindByIDNotFound verifies that querying a non-existent ID returns ErrCodeNotFound.
func TestFindByIDNotFound(t *testing.T) {
	repo, _ := setupRepo(t)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, "nonexistent-id-inttest")
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got: %v", err)
	}
}
