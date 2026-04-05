package redis_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/redis"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// newTestClient starts an in-process miniredis server and returns a connected
// go-redis client. The server is shut down automatically via t.Cleanup.
func newTestClient(t *testing.T) *goredis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	return goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
}

func TestTokenRepository_SaveAndFindByRaw(t *testing.T) {
	client := newTestClient(t)
	repo := redis.NewTokenRepository(client)
	ctx := context.Background()

	token := &domain.Token{
		ID:        "tok1",
		ClientID:  "client-a",
		Subject:   "user-1",
		Scopes:    []string{"read", "write"},
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
		TokenType: domain.TokenTypeBearer,
		Raw:       "raw-jwt-string",
	}

	if err := repo.Save(ctx, token); err != nil {
		t.Fatalf("Save returned unexpected error: %v", err)
	}

	got, err := repo.FindByRaw(ctx, token.Raw)
	if err != nil {
		t.Fatalf("FindByRaw returned unexpected error: %v", err)
	}
	if got.ID != token.ID {
		t.Errorf("ID mismatch: got %q, want %q", got.ID, token.ID)
	}
	if got.ClientID != token.ClientID {
		t.Errorf("ClientID mismatch: got %q, want %q", got.ClientID, token.ClientID)
	}
	if got.Subject != token.Subject {
		t.Errorf("Subject mismatch: got %q, want %q", got.Subject, token.Subject)
	}
}

func TestTokenRepository_FindByRaw_NotFound(t *testing.T) {
	client := newTestClient(t)
	repo := redis.NewTokenRepository(client)
	ctx := context.Background()

	_, err := repo.FindByRaw(ctx, "does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown token, got nil")
	}
	if !errors.Is(err, domain.ErrTokenNotFound) {
		t.Errorf("expected domain.ErrTokenNotFound, got: %v", err)
	}
}

func TestTokenRepository_Delete_RemovesToken(t *testing.T) {
	client := newTestClient(t)
	repo := redis.NewTokenRepository(client)
	ctx := context.Background()

	token := &domain.Token{
		ID:        "tok2",
		ClientID:  "client-b",
		Subject:   "user-2",
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
		TokenType: domain.TokenTypeBearer,
		Raw:       "raw-jwt-to-delete",
	}

	if err := repo.Save(ctx, token); err != nil {
		t.Fatalf("Save returned unexpected error: %v", err)
	}

	if err := repo.Delete(ctx, token.Raw); err != nil {
		t.Fatalf("Delete returned unexpected error: %v", err)
	}

	_, err := repo.FindByRaw(ctx, token.Raw)
	if !errors.Is(err, domain.ErrTokenNotFound) {
		t.Errorf("expected domain.ErrTokenNotFound after Delete, got: %v", err)
	}
}

func TestTokenRepository_Save_AlreadyExpiredNotStored(t *testing.T) {
	client := newTestClient(t)
	repo := redis.NewTokenRepository(client)
	ctx := context.Background()

	token := &domain.Token{
		ID:        "tok3",
		ClientID:  "client-c",
		Subject:   "user-3",
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(-time.Minute), // already expired
		IssuedAt:  time.Now().Add(-2 * time.Minute),
		TokenType: domain.TokenTypeBearer,
		Raw:       "expired-jwt-string",
	}

	if err := repo.Save(ctx, token); err != nil {
		t.Fatalf("Save on expired token returned unexpected error: %v", err)
	}

	_, err := repo.FindByRaw(ctx, token.Raw)
	if !errors.Is(err, domain.ErrTokenNotFound) {
		t.Errorf("expected domain.ErrTokenNotFound for expired-but-not-stored token, got: %v", err)
	}
}

func TestTokenRepository_Delete_NonExistentReturnsNotFound(t *testing.T) {
	client := newTestClient(t)
	repo := redis.NewTokenRepository(client)
	ctx := context.Background()

	err := repo.Delete(ctx, "never-issued")
	if err == nil {
		t.Fatal("expected error for non-existent token deletion, got nil")
	}
	var appErr *apperrors.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected *apperrors.AppError, got: %T %v", err, err)
	}
	if appErr.Code() != apperrors.ErrCodeNotFound {
		t.Errorf("expected ErrCodeNotFound, got: %s", appErr.Code())
	}
}
