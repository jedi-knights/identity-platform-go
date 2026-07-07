//go:build unit

package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/sqlite"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// setupRepo opens a fresh, uniquely-named SQLite file under t.TempDir() so
// every test gets its own isolated database — no shared state, no
// TEST_DATABASE_URL, no external service required.
func setupRepo(t *testing.T) (*sqlite.UserRepository, *sqlite.VerificationTokenRepository, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "identity.db")

	migrationDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening migration connection: %v", err)
	}
	if err := sqlite.RunMigrations(ctx, migrationDB); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if err := migrationDB.Close(); err != nil {
		t.Fatalf("closing migration connection: %v", err)
	}

	db, err := sqlite.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return sqlite.NewUserRepository(db), sqlite.NewVerificationTokenRepository(db), db
}

func newTestUser(suffix string) *domain.User {
	now := time.Now().UTC().Truncate(time.Second)
	return &domain.User{
		ID:           "test-id-" + suffix,
		Email:        "user-" + suffix + "@example.com",
		Name:         "Test User " + suffix,
		PasswordHash: "$2a$10$hashedpassword" + suffix,
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func TestUserRepository_SaveAndFindByID(t *testing.T) {
	// Arrange
	repo, _, _ := setupRepo(t)
	ctx := context.Background()
	user := newTestUser("save-find-1")

	// Act
	if err := repo.Save(ctx, user); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := repo.FindByID(ctx, user.ID)

	// Assert
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Email != user.Email {
		t.Errorf("Email: want %q, got %q", user.Email, got.Email)
	}
	if !got.CreatedAt.Equal(user.CreatedAt) {
		t.Errorf("CreatedAt: want %v, got %v", user.CreatedAt, got.CreatedAt)
	}
	if got.EmailVerifiedAt != nil {
		t.Errorf("EmailVerifiedAt: want nil, got %v", got.EmailVerifiedAt)
	}
}

func TestUserRepository_FindByEmail(t *testing.T) {
	// Arrange
	repo, _, _ := setupRepo(t)
	ctx := context.Background()
	user := newTestUser("find-email-1")
	if err := repo.Save(ctx, user); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	got, err := repo.FindByEmail(ctx, user.Email)

	// Assert
	if err != nil {
		t.Fatalf("FindByEmail: %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("ID: want %q, got %q", user.ID, got.ID)
	}
}

func TestUserRepository_Save_DuplicateEmail_Conflict(t *testing.T) {
	// Arrange
	repo, _, _ := setupRepo(t)
	ctx := context.Background()
	user := newTestUser("dup-1")
	if err := repo.Save(ctx, user); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	dup := newTestUser("dup-2")
	dup.Email = user.Email

	// Act
	err := repo.Save(ctx, dup)

	// Assert
	if !apperrors.IsConflict(err) {
		t.Errorf("expected ErrCodeConflict, got %v", err)
	}
}

func TestUserRepository_Update(t *testing.T) {
	// Arrange
	repo, _, _ := setupRepo(t)
	ctx := context.Background()
	user := newTestUser("update-1")
	if err := repo.Save(ctx, user); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	user.Name = "Updated Name"
	user.UpdatedAt = time.Now().UTC().Truncate(time.Second)
	if err := repo.Update(ctx, user); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := repo.FindByID(ctx, user.ID)

	// Assert
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Name != "Updated Name" {
		t.Errorf("Name: want %q, got %q", "Updated Name", got.Name)
	}
}

func TestUserRepository_Update_NotFound(t *testing.T) {
	// Arrange
	repo, _, _ := setupRepo(t)
	ctx := context.Background()
	user := newTestUser("update-missing-1")

	// Act
	err := repo.Update(ctx, user)

	// Assert
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestUserRepository_FindByID_NotFound(t *testing.T) {
	// Arrange
	repo, _, _ := setupRepo(t)
	ctx := context.Background()

	// Act
	_, err := repo.FindByID(ctx, "does-not-exist")

	// Assert
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestUserRepository_MarkEmailVerified(t *testing.T) {
	// Arrange
	repo, _, _ := setupRepo(t)
	ctx := context.Background()
	user := newTestUser("verify-1")
	if err := repo.Save(ctx, user); err != nil {
		t.Fatalf("Save: %v", err)
	}
	verifiedAt := time.Now().UTC().Truncate(time.Second)

	// Act
	if err := repo.MarkEmailVerified(ctx, user.ID, verifiedAt); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}
	got, err := repo.FindByID(ctx, user.ID)

	// Assert
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.EmailVerifiedAt == nil {
		t.Fatal("EmailVerifiedAt: want non-nil, got nil")
	}
	if !got.EmailVerifiedAt.Equal(verifiedAt) {
		t.Errorf("EmailVerifiedAt: want %v, got %v", verifiedAt, *got.EmailVerifiedAt)
	}
	if !got.IsEmailVerified() {
		t.Error("IsEmailVerified: want true")
	}
}

func TestUserRepository_MarkEmailVerified_NotFound(t *testing.T) {
	// Arrange
	repo, _, _ := setupRepo(t)
	ctx := context.Background()

	// Act
	err := repo.MarkEmailVerified(ctx, "does-not-exist", time.Now().UTC())

	// Assert
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestVerificationTokenRepository_SaveAndFindByHash(t *testing.T) {
	// Arrange
	userRepo, tokenRepo, _ := setupRepo(t)
	ctx := context.Background()
	user := newTestUser("token-user-1")
	if err := userRepo.Save(ctx, user); err != nil {
		t.Fatalf("Save user: %v", err)
	}
	token := &domain.VerificationToken{
		TokenHash: "hash-1",
		UserID:    user.ID,
		ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}

	// Act
	if err := tokenRepo.Save(ctx, token); err != nil {
		t.Fatalf("Save token: %v", err)
	}
	got, err := tokenRepo.FindByHash(ctx, token.TokenHash)

	// Assert
	if err != nil {
		t.Fatalf("FindByHash: %v", err)
	}
	if got.UserID != user.ID {
		t.Errorf("UserID: want %q, got %q", user.ID, got.UserID)
	}
	if got.UsedAt != nil {
		t.Errorf("UsedAt: want nil, got %v", got.UsedAt)
	}
}

func TestVerificationTokenRepository_MarkUsed(t *testing.T) {
	// Arrange
	userRepo, tokenRepo, _ := setupRepo(t)
	ctx := context.Background()
	user := newTestUser("token-user-2")
	if err := userRepo.Save(ctx, user); err != nil {
		t.Fatalf("Save user: %v", err)
	}
	token := &domain.VerificationToken{
		TokenHash: "hash-2",
		UserID:    user.ID,
		ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := tokenRepo.Save(ctx, token); err != nil {
		t.Fatalf("Save token: %v", err)
	}
	usedAt := time.Now().UTC().Truncate(time.Second)

	// Act
	if err := tokenRepo.MarkUsed(ctx, token.TokenHash, usedAt); err != nil {
		t.Fatalf("MarkUsed: %v", err)
	}
	got, err := tokenRepo.FindByHash(ctx, token.TokenHash)

	// Assert
	if err != nil {
		t.Fatalf("FindByHash: %v", err)
	}
	if got.UsedAt == nil || !got.UsedAt.Equal(usedAt) {
		t.Errorf("UsedAt: want %v, got %v", usedAt, got.UsedAt)
	}
}

func TestVerificationTokenRepository_MarkUsed_NotFound(t *testing.T) {
	// Arrange
	_, tokenRepo, _ := setupRepo(t)
	ctx := context.Background()

	// Act
	err := tokenRepo.MarkUsed(ctx, "does-not-exist", time.Now().UTC())

	// Assert
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestVerificationTokenRepository_DeleteExpired(t *testing.T) {
	// Arrange
	userRepo, tokenRepo, _ := setupRepo(t)
	ctx := context.Background()
	user := newTestUser("token-user-3")
	if err := userRepo.Save(ctx, user); err != nil {
		t.Fatalf("Save user: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	expired := &domain.VerificationToken{
		TokenHash: "hash-expired",
		UserID:    user.ID,
		ExpiresAt: now.Add(-time.Hour),
		CreatedAt: now.Add(-2 * time.Hour),
	}
	notExpired := &domain.VerificationToken{
		TokenHash: "hash-not-expired",
		UserID:    user.ID,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
	if err := tokenRepo.Save(ctx, expired); err != nil {
		t.Fatalf("Save expired: %v", err)
	}
	if err := tokenRepo.Save(ctx, notExpired); err != nil {
		t.Fatalf("Save notExpired: %v", err)
	}

	// Act
	deleted, err := tokenRepo.DeleteExpired(ctx, now)

	// Assert
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted: want 1, got %d", deleted)
	}
	if _, err := tokenRepo.FindByHash(ctx, expired.TokenHash); !apperrors.IsNotFound(err) {
		t.Errorf("expired token should be gone, got err=%v", err)
	}
	if _, err := tokenRepo.FindByHash(ctx, notExpired.TokenHash); err != nil {
		t.Errorf("notExpired token should remain, got err=%v", err)
	}
}

func TestRunMigrations_Idempotent(t *testing.T) {
	// Arrange
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "idempotent.db")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Act
	if err := sqlite.RunMigrations(ctx, db); err != nil {
		t.Fatalf("first RunMigrations: %v", err)
	}
	err = sqlite.RunMigrations(ctx, db)

	// Assert
	if err != nil {
		t.Fatalf("second RunMigrations should be a no-op, got error: %v", err)
	}
}
