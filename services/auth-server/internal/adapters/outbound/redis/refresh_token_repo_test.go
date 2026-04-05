//go:build unit

package redis_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/redis"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func newTestRefreshToken(raw string) *domain.RefreshToken {
	return &domain.RefreshToken{
		ID:        "rt-" + raw,
		Raw:       raw,
		ClientID:  "client-1",
		Subject:   "user-1",
		Scopes:    []string{"read"},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
}

func TestRefreshTokenRepository_SaveAndFindByRaw(t *testing.T) {
	client := newTestClient(t)
	repo := redis.NewRefreshTokenRepository(client)
	ctx := context.Background()

	rt := newTestRefreshToken("rt-abc")

	if err := repo.Save(ctx, rt); err != nil {
		t.Fatalf("Save returned unexpected error: %v", err)
	}

	got, err := repo.FindByRaw(ctx, rt.Raw)
	if err != nil {
		t.Fatalf("FindByRaw returned unexpected error: %v", err)
	}
	if got.ID != rt.ID {
		t.Errorf("ID = %q, want %q", got.ID, rt.ID)
	}
	if got.ClientID != rt.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, rt.ClientID)
	}
	if got.Subject != rt.Subject {
		t.Errorf("Subject = %q, want %q", got.Subject, rt.Subject)
	}
}

func TestRefreshTokenRepository_FindByRaw_NotFound(t *testing.T) {
	client := newTestClient(t)
	repo := redis.NewRefreshTokenRepository(client)
	ctx := context.Background()

	_, err := repo.FindByRaw(ctx, "does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown refresh token, got nil")
	}
	if !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Errorf("expected domain.ErrRefreshTokenNotFound, got: %v", err)
	}
}

func TestRefreshTokenRepository_Delete_RemovesToken(t *testing.T) {
	client := newTestClient(t)
	repo := redis.NewRefreshTokenRepository(client)
	ctx := context.Background()

	rt := newTestRefreshToken("rt-del")
	if err := repo.Save(ctx, rt); err != nil {
		t.Fatalf("Save returned unexpected error: %v", err)
	}

	if err := repo.Delete(ctx, rt.Raw); err != nil {
		t.Fatalf("Delete returned unexpected error: %v", err)
	}

	_, err := repo.FindByRaw(ctx, rt.Raw)
	if !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Errorf("expected domain.ErrRefreshTokenNotFound after Delete, got: %v", err)
	}
}

func TestRefreshTokenRepository_Delete_NotFound(t *testing.T) {
	client := newTestClient(t)
	repo := redis.NewRefreshTokenRepository(client)
	ctx := context.Background()

	err := repo.Delete(ctx, "never-issued")
	if err == nil {
		t.Fatal("expected error for non-existent refresh token deletion, got nil")
	}
	if !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Errorf("expected domain.ErrRefreshTokenNotFound, got: %v", err)
	}
}

func TestRefreshTokenRepository_Save_AlreadyExpired(t *testing.T) {
	client := newTestClient(t)
	repo := redis.NewRefreshTokenRepository(client)
	ctx := context.Background()

	rt := &domain.RefreshToken{
		ID:        "rt-expired",
		Raw:       "rt-expired",
		ClientID:  "client-1",
		Subject:   "user-1",
		Scopes:    []string{"read"},
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Minute), // already expired
	}

	err := repo.Save(ctx, rt)
	if err == nil {
		t.Fatal("expected error when saving already-expired refresh token, got nil")
	}
}
