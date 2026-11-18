//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/postgres"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

// setupList returns the repo, a live pool for direct seeding, and a
// cleanup func. TRUNCATE happens inside the shared setup() helper.
func setupList(t *testing.T) (*postgres.AccountRepository, *pgxpool.Pool, func()) {
	t.Helper()
	repo, cleanup := setup(t)
	// The shared setup() opens its own pool for the returned repo but
	// does not expose it; this file opens a second connection for
	// direct seeding of plans / account_plans rows.
	url := os.Getenv("ENTITLEMENTS_POSTGRES_TEST_URL")
	pool, err := postgres.Connect(context.Background(), url)
	if err != nil {
		cleanup()
		t.Fatalf("connect: %v", err)
	}
	return repo, pool, func() {
		pool.Close()
		cleanup()
	}
}

// TestListByUserID_ReturnsEmptyForUnknownUser confirms an unknown user
// yields an empty slice (nil error).
func TestListByUserID_ReturnsEmptyForUnknownUser(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()

	rows, err := repo.ListByUserID(context.Background(), "u-nobody")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("want 0 rows, got %d", len(rows))
	}
}

// TestListByUserID_ReturnsOwnerRow seeds a personal account and
// confirms the join returns exactly one owner-role row with no plan.
func TestListByUserID_ReturnsOwnerRow(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()

	acc, err := repo.UpsertPersonalAccount(context.Background(), "u-list-1", "u1@example.com")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	rows, err := repo.ListByUserID(context.Background(), "u-list-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	assertOwnerRow(t, rows, acc.ID, "u1@example.com")
}

// assertOwnerRow verifies the shape of a single owner-seat row from
// ListByUserID. Extracted to keep the test under gocyclo.
func assertOwnerRow(t *testing.T, rows []domain.UserSeatSummary, wantAccountID, wantDisplayName string) {
	t.Helper()
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].AccountID != wantAccountID {
		t.Errorf("AccountID = %q, want %q", rows[0].AccountID, wantAccountID)
	}
	if rows[0].AccountDisplayName != wantDisplayName {
		t.Errorf("AccountDisplayName = %q, want %q", rows[0].AccountDisplayName, wantDisplayName)
	}
	if string(rows[0].Role) != "owner" {
		t.Errorf("Role = %q, want owner", rows[0].Role)
	}
	if rows[0].Plan != nil {
		t.Errorf("Plan = %+v, want nil (no active plan seeded)", rows[0].Plan)
	}
}

// seedPlan inserts a plan whose code is the given prefix plus a unique suffix
// and removes it when the test ends. plans.code is unique and setup only
// truncates accounts (which cascades to account_plans, not plans), so a fixed
// code would collide with the row left by the previous run. It returns the
// generated code and the plan's id.
func seedPlan(t *testing.T, pool *pgxpool.Pool, codePrefix, name, tier string, allowance int) (code, id string) {
	t.Helper()
	ctx := context.Background()
	code = fmt.Sprintf("%s-%d", codePrefix, time.Now().UnixNano())
	err := pool.QueryRow(ctx,
		`INSERT INTO plans (code, display_name, tier, seat_allowance)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id`,
		code, name, tier, allowance,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seed plan %q: %v", code, err)
	}
	t.Cleanup(func() { deletePlan(t, code, id) })
	return code, id
}

// deletePlan removes a seeded plan and the account_plans rows that reference it
// (account_plans.plan_id is ON DELETE RESTRICT). It uses its own connection: the
// test's pool is closed by the deferred cleanup before t.Cleanup callbacks run.
func deletePlan(t *testing.T, code, id string) {
	t.Helper()
	ctx := context.Background()
	pool, err := postgres.Connect(ctx, os.Getenv("ENTITLEMENTS_POSTGRES_TEST_URL"))
	if err != nil {
		t.Errorf("cleanup connect for plan %q: %v", code, err)
		return
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DELETE FROM account_plans WHERE plan_id = $1`, id); err != nil {
		t.Errorf("cleanup account_plans for %q: %v", code, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM plans WHERE id = $1`, id); err != nil {
		t.Errorf("cleanup plan %q: %v", code, err)
	}
}

// TestListByUserID_PopulatesPlanFromActiveAccountPlan seeds a plan and
// an active account_plans row, then confirms the LEFT JOIN materialises
// the plan summary onto the row.
func TestListByUserID_PopulatesPlanFromActiveAccountPlan(t *testing.T) {
	repo, pool, cleanup := setupList(t)
	defer cleanup()
	ctx := context.Background()

	acc, err := repo.UpsertPersonalAccount(ctx, "u-plan-1", "up1@example.com")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	planCode, planID := seedPlan(t, pool, "touchline-club", "Touchline Club", "club", 10)
	if _, err := pool.Exec(ctx,
		`INSERT INTO account_plans (account_id, plan_id, valid_from) VALUES ($1, $2, $3)`,
		acc.ID, planID, time.Now().UTC(),
	); err != nil {
		t.Fatalf("seed account_plans: %v", err)
	}

	rows, err := repo.ListByUserID(ctx, "u-plan-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].Plan == nil {
		t.Fatalf("want 1 row with plan, got %+v", rows)
	}
	if rows[0].Plan.Code != planCode {
		t.Errorf("Plan.Code = %q, want %q", rows[0].Plan.Code, planCode)
	}
}

// TestListByUserID_ExpiredPlanIsExcluded seeds a plan whose
// valid_until is set (i.e. no longer active) and confirms the row
// comes back with Plan == nil — the WHERE ap.valid_until IS NULL
// predicate must exclude historical rows.
func TestListByUserID_ExpiredPlanIsExcluded(t *testing.T) {
	repo, pool, cleanup := setupList(t)
	defer cleanup()
	ctx := context.Background()

	acc, err := repo.UpsertPersonalAccount(ctx, "u-expired", "ex@example.com")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	_, planID := seedPlan(t, pool, "touchline-free-expired", "Free (Expired)", "free", 1)
	past := time.Now().UTC().Add(-24 * time.Hour)
	if _, err := pool.Exec(ctx,
		`INSERT INTO account_plans (account_id, plan_id, valid_from, valid_until)
		 VALUES ($1, $2, $3, $4)`,
		acc.ID, planID, past.Add(-24*time.Hour), past,
	); err != nil {
		t.Fatalf("seed expired account_plans: %v", err)
	}

	rows, _ := repo.ListByUserID(ctx, "u-expired")
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].Plan != nil {
		t.Errorf("Plan = %+v, want nil (only expired plan)", rows[0].Plan)
	}
}
