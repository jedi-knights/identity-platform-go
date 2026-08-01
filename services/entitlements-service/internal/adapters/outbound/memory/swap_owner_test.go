package memory_test

import (
	"context"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

func TestSwapOwner_FlipsRoles(t *testing.T) {
	repo := memory.NewAccountRepository()
	acc, _ := repo.UpsertPersonalAccount(context.Background(), "u-owner", "o@example.com")
	repo.AddMemberSeat(acc.ID, "u-member", domain.RoleMember)

	if err := repo.SwapOwner(context.Background(), acc.ID, "u-owner", "u-member"); err != nil {
		t.Fatalf("SwapOwner: %v", err)
	}
	oldOwner, _ := repo.FindSeat(context.Background(), acc.ID, "u-owner")
	newOwner, _ := repo.FindSeat(context.Background(), acc.ID, "u-member")
	if oldOwner.Role != domain.RoleAdmin {
		t.Errorf("old owner = %q, want admin", oldOwner.Role)
	}
	if newOwner.Role != domain.RoleOwner {
		t.Errorf("new owner = %q, want owner", newOwner.Role)
	}
}

func TestSwapOwner_MissingTarget_NotFound(t *testing.T) {
	repo := memory.NewAccountRepository()
	acc, _ := repo.UpsertPersonalAccount(context.Background(), "u-owner", "o@example.com")

	err := repo.SwapOwner(context.Background(), acc.ID, "u-owner", "u-ghost")
	if !apperrors.IsNotFound(err) {
		t.Errorf("want not-found, got %v", err)
	}
}

func TestSwapOwner_CurrentOwnerRoleMismatch_Conflict(t *testing.T) {
	repo := memory.NewAccountRepository()
	acc, _ := repo.UpsertPersonalAccount(context.Background(), "u-owner", "o@example.com")
	repo.AddMemberSeat(acc.ID, "u-admin", domain.RoleAdmin)
	repo.AddMemberSeat(acc.ID, "u-member", domain.RoleMember)

	// Attempt to demote u-admin (who is admin, not owner) — must
	// conflict, not silently proceed.
	err := repo.SwapOwner(context.Background(), acc.ID, "u-admin", "u-member")
	if !apperrors.IsConflict(err) {
		t.Errorf("want conflict, got %v", err)
	}
}
