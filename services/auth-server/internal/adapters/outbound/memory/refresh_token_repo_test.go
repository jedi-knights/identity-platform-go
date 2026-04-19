//go:build unit

package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/memory"
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
	repo := memory.NewRefreshTokenRepository()
	rt := newTestRefreshToken("rt-abc")

	if err := repo.Save(context.Background(), rt); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindByRaw(context.Background(), "rt-abc")
	if err != nil {
		t.Fatalf("FindByRaw: %v", err)
	}
	if got.ID != rt.ID {
		t.Errorf("ID = %q, want %q", got.ID, rt.ID)
	}
	if got.ClientID != rt.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, rt.ClientID)
	}
}

func TestRefreshTokenRepository_FindByRaw_NotFound(t *testing.T) {
	repo := memory.NewRefreshTokenRepository()

	_, err := repo.FindByRaw(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Errorf("expected ErrRefreshTokenNotFound, got: %v", err)
	}
}

func TestRefreshTokenRepository_Delete_RemovesToken(t *testing.T) {
	repo := memory.NewRefreshTokenRepository()
	rt := newTestRefreshToken("rt-del")

	if err := repo.Save(context.Background(), rt); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := repo.Delete(context.Background(), "rt-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := repo.FindByRaw(context.Background(), "rt-del")
	if !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Errorf("expected ErrRefreshTokenNotFound after Delete, got: %v", err)
	}
}

func TestRefreshTokenRepository_Delete_NotFound(t *testing.T) {
	repo := memory.NewRefreshTokenRepository()

	err := repo.Delete(context.Background(), "never-stored")
	if !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Errorf("expected ErrRefreshTokenNotFound for missing key, got: %v", err)
	}
}
