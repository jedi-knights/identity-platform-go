package memory_test

import (
	"context"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

func TestListByUserID_ReturnsEmptyForUnknownUser(t *testing.T) {
	repo := memory.NewAccountRepository()

	got, err := repo.ListByUserID(context.Background(), "u-nobody")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 rows, got %d", len(got))
	}
}

func TestListByUserID_ReturnsOwnerSeatFromPersonalAccount(t *testing.T) {
	repo := memory.NewAccountRepository()
	acc, err := repo.UpsertPersonalAccount(context.Background(), "u-1", "u1@example.com")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	rows, err := repo.ListByUserID(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	assertOwnerSeatRow(t, rows[0], acc.ID, "u1@example.com")
}

// assertOwnerSeatRow verifies every field on a UserSeatSummary row
// returned by ListByUserID for a freshly-upserted personal account with
// no plan attached. Extracted from
// TestListByUserID_ReturnsOwnerSeatFromPersonalAccount to keep the test
// under the gocyclo cap while covering every field.
func assertOwnerSeatRow(t *testing.T, row domain.UserSeatSummary, wantAccountID, wantDisplayName string) {
	t.Helper()
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"AccountID", row.AccountID, wantAccountID},
		{"Role", string(row.Role), string(domain.RoleOwner)},
		{"AccountDisplayName", row.AccountDisplayName, wantDisplayName},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("row.%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	if row.Plan != nil {
		t.Errorf("Plan = %+v, want nil (no plan attached)", row.Plan)
	}
}

func TestListByUserID_PopulatesPlanWhenAttached(t *testing.T) {
	repo := memory.NewAccountRepository()
	acc, _ := repo.UpsertPersonalAccount(context.Background(), "u-1", "u1@example.com")
	repo.SetActivePlan(acc.ID, domain.PlanSummary{
		ID:          "plan-1",
		Code:        "touchline-club",
		DisplayName: "Touchline Club",
	})

	rows, _ := repo.ListByUserID(context.Background(), "u-1")
	if len(rows) != 1 || rows[0].Plan == nil {
		t.Fatalf("want row with plan, got %+v", rows)
	}
	if rows[0].Plan.Code != "touchline-club" {
		t.Errorf("Plan.Code = %q, want touchline-club", rows[0].Plan.Code)
	}
}

func TestListByUserID_ReturnsSeatsFromMultipleAccounts(t *testing.T) {
	repo := memory.NewAccountRepository()
	ctx := context.Background()
	_, _ = repo.UpsertPersonalAccount(ctx, "u-1", "u1@example.com")
	_, _ = repo.UpsertPersonalAccount(ctx, "u-other", "other@example.com")

	rows, err := repo.ListByUserID(ctx, "u-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Errorf("cross-user leak: want 1 seat for u-1, got %d", len(rows))
	}
}
