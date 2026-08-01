package memory_test

import (
	"context"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

func TestFindSeat_ReturnsOwnerAfterUpsert(t *testing.T) {
	repo := memory.NewAccountRepository()
	acc, err := repo.UpsertPersonalAccount(context.Background(), "u-1", "u1@example.com")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := repo.FindSeat(context.Background(), acc.ID, "u-1")
	if err != nil {
		t.Fatalf("FindSeat: %v", err)
	}
	if got.Role != domain.RoleOwner {
		t.Errorf("role = %q, want owner", got.Role)
	}
}

func TestFindSeat_MissingReturnsNotFound(t *testing.T) {
	repo := memory.NewAccountRepository()
	acc, _ := repo.UpsertPersonalAccount(context.Background(), "u-1", "u1@example.com")

	_, err := repo.FindSeat(context.Background(), acc.ID, "u-ghost")
	if !apperrors.IsNotFound(err) {
		t.Fatalf("want not-found, got %v", err)
	}
}

func TestRemove_DropsSeat(t *testing.T) {
	repo := memory.NewAccountRepository()
	acc, _ := repo.UpsertPersonalAccount(context.Background(), "u-1", "u1@example.com")
	repo.AddMemberSeat(acc.ID, "u-2", domain.RoleMember)

	if err := repo.Remove(context.Background(), acc.ID, "u-2"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	_, err := repo.FindSeat(context.Background(), acc.ID, "u-2")
	if !apperrors.IsNotFound(err) {
		t.Errorf("want not-found after Remove, got %v", err)
	}
	// Owner seat must remain — Remove must not sweep siblings.
	if _, err := repo.FindSeat(context.Background(), acc.ID, "u-1"); err != nil {
		t.Errorf("owner disappeared after member removal: %v", err)
	}
}

func TestRemove_MissingReturnsNotFound(t *testing.T) {
	repo := memory.NewAccountRepository()
	acc, _ := repo.UpsertPersonalAccount(context.Background(), "u-1", "u1@example.com")

	err := repo.Remove(context.Background(), acc.ID, "u-never-existed")
	if !apperrors.IsNotFound(err) {
		t.Errorf("want not-found, got %v", err)
	}
}
