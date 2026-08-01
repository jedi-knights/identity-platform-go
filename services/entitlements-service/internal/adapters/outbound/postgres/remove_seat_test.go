//go:build integration

package postgres_test

import (
	"context"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

func TestPostgresFindSeat_ReturnsOwnerAfterUpsert(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()
	acc, err := repo.UpsertPersonalAccount(context.Background(), "user-owner", "o@example.com")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	seat, err := repo.FindSeat(context.Background(), acc.ID, "user-owner")
	if err != nil {
		t.Fatalf("FindSeat: %v", err)
	}
	if seat.Role != domain.RoleOwner {
		t.Errorf("role = %q, want owner", seat.Role)
	}
}

func TestPostgresFindSeat_MissingReturnsNotFound(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()
	acc, _ := repo.UpsertPersonalAccount(context.Background(), "user-a", "a@example.com")

	_, err := repo.FindSeat(context.Background(), acc.ID, "user-ghost")
	if !apperrors.IsNotFound(err) {
		t.Errorf("want not-found, got %v", err)
	}
}

func TestPostgresRemove_MissingReturnsNotFound(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()
	acc, _ := repo.UpsertPersonalAccount(context.Background(), "user-a", "a@example.com")

	err := repo.Remove(context.Background(), acc.ID, "user-never-existed")
	if !apperrors.IsNotFound(err) {
		t.Errorf("want not-found, got %v", err)
	}
}
