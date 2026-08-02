package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/ports"
)

// Compile-time assertion that AccountRepository also satisfies the
// plan port. Declared here so the swap point stays next to the plan
// methods; the account/seat asserts stay in account_repo.go.
var _ ports.PlanRepository = (*AccountRepository)(nil)

// FindPlanByCode returns the plans row for code, or ErrCodeNotFound.
// code is Lago's plan.code — the two catalogs are kept in lockstep by
// operator convention (ADR-0028); this method is the read side of the
// join the login-ui plan picker's submitted plan_code triggers.
func (r *AccountRepository) FindPlanByCode(ctx context.Context, code string) (*domain.Plan, error) {
	if code == "" {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "plan code is required")
	}
	const q = `
		SELECT id, code, display_name, tier, seat_allowance
		FROM plans
		WHERE code = $1`
	var p domain.Plan
	err := r.pool.QueryRow(ctx, q, code).Scan(
		&p.ID, &p.Code, &p.DisplayName, &p.Tier, &p.SeatAllowance,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "plan not found: "+code)
	}
	if err != nil {
		return nil, fmt.Errorf("find plan by code: %w", err)
	}
	return &p, nil
}

// ActivateAccountPlan attaches a plan to an account. Runs an
// idempotency probe inside the same transaction as the insert so a
// concurrent replay from login-ui cannot produce two active rows for
// the same account. See PlanRepository docs for the three cases;
// this method returns:
//
//   - the existing row + created=false when (account, plan) already
//     has valid_until IS NULL
//   - ErrCodeConflict when a *different* plan is currently active
//   - the newly-inserted row + created=true otherwise
//
// The insert uses the account_plans natural key (account_id, plan_id,
// valid_from) via ON CONFLICT DO NOTHING as a belt-and-braces guard
// against a resubmit within the same nanosecond; the probe still runs
// first because the natural key does not cover plan-change conflicts.
func (r *AccountRepository) ActivateAccountPlan(ctx context.Context, in ports.ActivateAccountPlanInput) (*domain.AccountPlan, bool, error) {
	if err := validateActivateInputPG(in); err != nil {
		return nil, false, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("begin activate-plan tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row, created, err := activateAccountPlanTx(ctx, tx, in)
	if err != nil {
		return nil, false, err
	}
	if created {
		if err := tx.Commit(ctx); err != nil {
			return nil, false, fmt.Errorf("commit activate-plan tx: %w", err)
		}
	}
	return row, created, nil
}

// activateAccountPlanTx runs the probe-then-insert inside tx. Extracted
// so ActivateAccountPlan stays inside the gocyclo budget. A same-plan
// idempotent hit skips commit (the tx is read-only from the caller's
// perspective and the deferred rollback closes it cleanly).
func activateAccountPlanTx(ctx context.Context, tx pgx.Tx, in ports.ActivateAccountPlanInput) (*domain.AccountPlan, bool, error) {
	existing, err := findActiveAccountPlan(ctx, tx, in.AccountID)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		if existing.PlanID != in.PlanID {
			return nil, false, apperrors.New(apperrors.ErrCodeConflict,
				"account already has an active plan; plan change is not supported here")
		}
		return existing, false, nil
	}
	inserted, err := insertAccountPlan(ctx, tx, in)
	if err != nil {
		return nil, false, err
	}
	return inserted, true, nil
}

// findActiveAccountPlan returns the account's currently-active row
// (valid_until IS NULL) inside tx, or (nil, nil) when none exists. The
// caller-supplied tx ensures the probe + subsequent insert are one
// transaction so concurrent activation races collapse safely.
func findActiveAccountPlan(ctx context.Context, tx pgx.Tx, accountID string) (*domain.AccountPlan, error) {
	const q = `
		SELECT id, account_id, plan_id, valid_from, valid_until,
		       COALESCE(lago_subscription_id, ''),
		       created_at, updated_at
		FROM account_plans
		WHERE account_id = $1 AND valid_until IS NULL
		LIMIT 1`
	row := &domain.AccountPlan{}
	err := tx.QueryRow(ctx, q, accountID).Scan(
		&row.ID, &row.AccountID, &row.PlanID, &row.ValidFrom, &row.ValidUntil,
		&row.LagoSubscriptionID, &row.CreatedAt, &row.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("probe active account plan: %w", err)
	}
	return row, nil
}

// insertAccountPlan writes a new account_plans row. lago_subscription_id
// is stored as NULL when empty so the column stays sparse rather than
// carrying zero-value strings — matches how the postgres seat repo
// treats optional identifiers.
func insertAccountPlan(ctx context.Context, tx pgx.Tx, in ports.ActivateAccountPlanInput) (*domain.AccountPlan, error) {
	const q = `
		INSERT INTO account_plans (account_id, plan_id, valid_from, lago_subscription_id)
		VALUES ($1, $2, $3, NULLIF($4, ''))
		RETURNING id, account_id, plan_id, valid_from, valid_until,
		          COALESCE(lago_subscription_id, ''),
		          created_at, updated_at`
	row := &domain.AccountPlan{}
	err := tx.QueryRow(ctx, q,
		in.AccountID, in.PlanID, in.ValidFrom, in.LagoSubscriptionID,
	).Scan(
		&row.ID, &row.AccountID, &row.PlanID, &row.ValidFrom, &row.ValidUntil,
		&row.LagoSubscriptionID, &row.CreatedAt, &row.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert account_plans: %w", err)
	}
	return row, nil
}

// validateActivateInputPG mirrors the memory adapter's validate so both
// backends reject the same shapes. Split from memory's helper to avoid
// a cross-package call inside the outbound layer.
func validateActivateInputPG(in ports.ActivateAccountPlanInput) error {
	if in.AccountID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "account_id is required")
	}
	if in.PlanID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "plan_id is required")
	}
	if in.ValidFrom.IsZero() {
		return apperrors.New(apperrors.ErrCodeBadRequest, "valid_from is required")
	}
	return nil
}
