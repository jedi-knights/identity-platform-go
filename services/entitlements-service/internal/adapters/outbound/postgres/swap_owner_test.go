//go:build integration

package postgres_test

import (
	"context"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

func TestPostgresSwapOwner_MissingTarget_NotFound(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()
	acc, _ := repo.UpsertPersonalAccount(context.Background(), "u-owner", "o@example.com")

	err := repo.SwapOwner(context.Background(), acc.ID, "u-owner", "u-ghost")
	if !apperrors.IsNotFound(err) {
		t.Errorf("want not-found, got %v", err)
	}

	// Sanity: current owner must still be owner — the tx must have
	// rolled back the demote when the promote failed.
	seat, err := repo.FindSeat(context.Background(), acc.ID, "u-owner")
	if err != nil {
		t.Fatalf("FindSeat after failed swap: %v", err)
	}
	if seat.Role != domain.RoleOwner {
		t.Errorf("current owner role after failed swap = %q, want owner (tx must rollback)", seat.Role)
	}
}

func TestPostgresSwapOwner_CurrentOwnerRoleMismatch_Conflict(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()
	acc, _ := repo.UpsertPersonalAccount(context.Background(), "u-owner", "o@example.com")

	// Attempt to demote a non-existent user labelled as owner; the
	// demote UPDATE affects 0 rows and surfaces as conflict.
	err := repo.SwapOwner(context.Background(), acc.ID, "u-stranger", "u-owner")
	if !apperrors.IsConflict(err) {
		t.Errorf("want conflict, got %v", err)
	}
}
