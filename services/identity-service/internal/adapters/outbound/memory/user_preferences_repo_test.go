package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/memory"
)

func TestUserPreferencesRepository_Get_MissingReturnsNilNil(t *testing.T) {
	repo := memory.NewUserPreferencesRepository()

	got, err := repo.Get(context.Background(), "u-nobody")
	if err != nil {
		t.Fatalf("Get on missing user: unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("Get on missing user: want nil row, got %+v", got)
	}
}

func TestUserPreferencesRepository_SetActiveAccount_CreatesRow(t *testing.T) {
	repo := memory.NewUserPreferencesRepository()
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	if err := repo.SetActiveAccount(context.Background(), "u1", "acc-1", now); err != nil {
		t.Fatalf("SetActiveAccount: %v", err)
	}

	got, err := repo.Get(context.Background(), "u1")
	if err != nil {
		t.Fatalf("Get after Set: %v", err)
	}
	if got == nil {
		t.Fatalf("Get after Set: want row, got nil")
	}
	if got.UserID != "u1" || got.ActiveAccountID != "acc-1" || !got.UpdatedAt.Equal(now) {
		t.Errorf("Get: unexpected row: %+v", got)
	}
}

func TestUserPreferencesRepository_SetActiveAccount_UpdatesRow(t *testing.T) {
	repo := memory.NewUserPreferencesRepository()
	ctx := context.Background()
	t0 := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)

	if err := repo.SetActiveAccount(ctx, "u1", "acc-1", t0); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetActiveAccount(ctx, "u1", "acc-2", t1); err != nil {
		t.Fatal(err)
	}

	got, _ := repo.Get(ctx, "u1")
	if got.ActiveAccountID != "acc-2" {
		t.Errorf("update: want acc-2, got %q", got.ActiveAccountID)
	}
	if !got.UpdatedAt.Equal(t1) {
		t.Errorf("update: want UpdatedAt %v, got %v", t1, got.UpdatedAt)
	}
}

func TestUserPreferencesRepository_Get_NoAliasing(t *testing.T) {
	repo := memory.NewUserPreferencesRepository()
	ctx := context.Background()
	now := time.Now()
	_ = repo.SetActiveAccount(ctx, "u1", "acc-1", now)

	got, _ := repo.Get(ctx, "u1")
	got.ActiveAccountID = "mutated"

	got2, _ := repo.Get(ctx, "u1")
	if got2.ActiveAccountID != "acc-1" {
		t.Errorf("aliasing: stored value changed to %q after caller mutation", got2.ActiveAccountID)
	}
}

func TestUserPreferencesRepository_Get_PerUserIsolation(t *testing.T) {
	repo := memory.NewUserPreferencesRepository()
	ctx := context.Background()
	now := time.Now()
	_ = repo.SetActiveAccount(ctx, "u1", "acc-1", now)
	_ = repo.SetActiveAccount(ctx, "u2", "acc-2", now)

	got1, _ := repo.Get(ctx, "u1")
	got2, _ := repo.Get(ctx, "u2")
	if got1.ActiveAccountID != "acc-1" || got2.ActiveAccountID != "acc-2" {
		t.Errorf("cross-user leak: u1=%s u2=%s", got1.ActiveAccountID, got2.ActiveAccountID)
	}
}
