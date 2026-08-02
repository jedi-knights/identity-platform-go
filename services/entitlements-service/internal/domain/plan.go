package domain

import "time"

// Plan is the catalog projection matching one row of the plans table.
// Kept minimal — only the fields callers outside the catalog editor
// consume. Seat allowance and tier travel here so the account-activation
// path can log the tier without a second lookup.
type Plan struct {
	ID            string
	Code          string
	DisplayName   string
	Tier          string
	SeatAllowance int
}

// AccountPlan is one row of the account_plans table — the mapping of
// an account to a plan with a validity window. ValidUntil == nil means
// the row is the account's currently-active plan; a plan change (or
// cancellation) closes the row by setting ValidUntil.
//
// LagoSubscriptionID is empty on the free-plan path (Lago requires no
// subscription for a free plan) and populated by the paid-plan flow
// once Lago's subscription create succeeds. Downstream reconciliation
// keys off this value; keep it empty rather than zero-value so the
// column stays NULL in Postgres.
type AccountPlan struct {
	ID                 string
	AccountID          string
	PlanID             string
	ValidFrom          time.Time
	ValidUntil         *time.Time
	LagoSubscriptionID string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}
