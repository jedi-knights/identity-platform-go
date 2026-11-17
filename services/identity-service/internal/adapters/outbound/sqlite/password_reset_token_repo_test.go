//go:build unit

package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/sqlite"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// newResetRepoWithUser returns a reset-token repo plus a persisted user the
// token rows can reference (password_reset_tokens.user_id is a foreign key).
func newResetRepoWithUser(t *testing.T) (*sqlite.PasswordResetTokenRepository, *domain.User) {
	t.Helper()
	userRepo, _, db := setupRepo(t)
	user := newTestUser("reset-1")
	if err := userRepo.Save(context.Background(), user); err != nil {
		t.Fatalf("saving user: %v", err)
	}
	return sqlite.NewPasswordResetTokenRepository(db), user
}

func TestPasswordResetTokenRepository_SaveAndFindByHash(t *testing.T) {
	ctx := context.Background()
	repo, user := newResetRepoWithUser(t)
	now := time.Now().UTC().Truncate(time.Second)
	token := &domain.PasswordResetToken{
		TokenHash: "reset-hash-1",
		UserID:    user.ID,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}

	if err := repo.Save(ctx, token); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := repo.FindByHash(ctx, token.TokenHash)
	if err != nil {
		t.Fatalf("FindByHash: %v", err)
	}

	if got.UserID != user.ID || !got.ExpiresAt.Equal(token.ExpiresAt) || !got.CreatedAt.Equal(now) || got.UsedAt != nil {
		t.Errorf("round trip mismatch: got %+v, want %+v", got, token)
	}
}

func TestPasswordResetTokenRepository_FindByHash_NotFound(t *testing.T) {
	repo, _ := newResetRepoWithUser(t)

	_, err := repo.FindByHash(context.Background(), "missing")

	if !apperrors.IsNotFound(err) {
		t.Errorf("want not-found error, got %v", err)
	}
}

func TestPasswordResetTokenRepository_MarkUsed(t *testing.T) {
	ctx := context.Background()
	repo, user := newResetRepoWithUser(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := repo.Save(ctx, &domain.PasswordResetToken{TokenHash: "h", UserID: user.ID, ExpiresAt: now.Add(time.Hour), CreatedAt: now}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := repo.MarkUsed(ctx, "h", now); err != nil {
		t.Fatalf("MarkUsed: %v", err)
	}
	got, err := repo.FindByHash(ctx, "h")
	if err != nil {
		t.Fatalf("FindByHash: %v", err)
	}

	if got.UsedAt == nil || !got.UsedAt.Equal(now) {
		t.Errorf("UsedAt = %v, want %v", got.UsedAt, now)
	}
	if err := repo.MarkUsed(ctx, "missing", now); !apperrors.IsNotFound(err) {
		t.Errorf("MarkUsed(missing) = %v, want not-found", err)
	}
}

func TestPasswordResetTokenRepository_DeleteExpired(t *testing.T) {
	ctx := context.Background()
	repo, user := newResetRepoWithUser(t)
	now := time.Now().UTC().Truncate(time.Second)
	for hash, exp := range map[string]time.Time{"old": now.Add(-time.Hour), "fresh": now.Add(time.Hour)} {
		if err := repo.Save(ctx, &domain.PasswordResetToken{TokenHash: hash, UserID: user.ID, ExpiresAt: exp, CreatedAt: now}); err != nil {
			t.Fatalf("Save %s: %v", hash, err)
		}
	}

	n, err := repo.DeleteExpired(ctx, now)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	if n != 1 {
		t.Errorf("deleted %d rows, want 1", n)
	}
	if _, err := repo.FindByHash(ctx, "fresh"); err != nil {
		t.Errorf("fresh token should survive: %v", err)
	}
}
