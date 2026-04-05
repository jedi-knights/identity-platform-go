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

func newTestToken(raw string) *domain.Token {
	return &domain.Token{
		ID:        "tok-" + raw,
		ClientID:  "client-1",
		Subject:   "user-1",
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
		TokenType: domain.TokenTypeBearer,
		Raw:       raw,
	}
}

func TestTokenRepository_SaveAndFindByRaw(t *testing.T) {
	repo := memory.NewTokenRepository()
	tok := newTestToken("raw-abc")

	if err := repo.Save(context.Background(), tok); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindByRaw(context.Background(), "raw-abc")
	if err != nil {
		t.Fatalf("FindByRaw: %v", err)
	}
	if got.ID != tok.ID {
		t.Errorf("ID = %q, want %q", got.ID, tok.ID)
	}
}

func TestTokenRepository_FindByRaw_NotFound(t *testing.T) {
	repo := memory.NewTokenRepository()

	_, err := repo.FindByRaw(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, domain.ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound, got: %v", err)
	}
}

func TestTokenRepository_Delete_RemovesToken(t *testing.T) {
	repo := memory.NewTokenRepository()
	tok := newTestToken("raw-del")

	if err := repo.Save(context.Background(), tok); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := repo.Delete(context.Background(), "raw-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := repo.FindByRaw(context.Background(), "raw-del")
	if !errors.Is(err, domain.ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound after Delete, got: %v", err)
	}
}

func TestTokenRepository_Delete_NonExistent_ReturnsNotFound(t *testing.T) {
	repo := memory.NewTokenRepository()
	// Delete on a non-existent key must return ErrTokenNotFound — consistent with the Redis adapter.
	err := repo.Delete(context.Background(), "never-stored")
	if !errors.Is(err, domain.ErrTokenNotFound) {
		t.Errorf("Delete of non-existent key: got %v, want ErrTokenNotFound", err)
	}
}
