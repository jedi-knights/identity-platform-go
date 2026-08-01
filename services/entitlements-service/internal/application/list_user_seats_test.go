package application_test

import (
	"context"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

func newListUserSeatsSvc() (*application.AccountService, *memory.AccountRepository) {
	repo := memory.NewAccountRepository()
	svc := application.NewAccountService(repo)
	return svc, repo
}

func TestListUserSeats_RejectsEmptyUserID(t *testing.T) {
	svc, _ := newListUserSeatsSvc()

	_, err := svc.ListUserSeats(context.Background(), "")
	if !apperrors.IsBadRequest(err) {
		t.Fatalf("want bad-request, got %v", err)
	}
}

func TestListUserSeats_EmptySliceForUnknownUser(t *testing.T) {
	svc, _ := newListUserSeatsSvc()

	rows, err := svc.ListUserSeats(context.Background(), "u-nobody")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("want empty slice, got %d rows", len(rows))
	}
}

func TestListUserSeats_ReturnsOwnerRow(t *testing.T) {
	svc, repo := newListUserSeatsSvc()
	acc, err := repo.UpsertPersonalAccount(context.Background(), "u-1", "u1@example.com")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	rows, err := svc.ListUserSeats(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].AccountID != acc.ID {
		t.Errorf("AccountID = %q, want %q", rows[0].AccountID, acc.ID)
	}
	if rows[0].Role != domain.RoleOwner {
		t.Errorf("Role = %q, want owner", rows[0].Role)
	}
}

func TestListUserSeats_IncludesPlanWhenAttached(t *testing.T) {
	svc, repo := newListUserSeatsSvc()
	acc, _ := repo.UpsertPersonalAccount(context.Background(), "u-1", "u1@example.com")
	repo.SetActivePlan(acc.ID, domain.PlanSummary{
		ID:          "plan-1",
		Code:        "touchline-club",
		DisplayName: "Touchline Club",
	})

	rows, _ := svc.ListUserSeats(context.Background(), "u-1")
	if len(rows) != 1 || rows[0].Plan == nil {
		t.Fatalf("want row with plan, got %+v", rows)
	}
	if rows[0].Plan.Code != "touchline-club" {
		t.Errorf("Plan.Code = %q, want touchline-club", rows[0].Plan.Code)
	}
}
