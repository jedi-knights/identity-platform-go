package memory

import (
	"context"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/ports"
)

// Compile-time assertion that AccountRepository satisfies PlanRepository.
// Declared here so the plan-catalog surface stays discoverable next to
// its methods; the account/seat asserts stay in account_repo.go.
var _ ports.PlanRepository = (*AccountRepository)(nil)

// AddPlan seeds a plan into the catalog for tests. Real production seed
// happens via SQL fixtures in the postgres adapter's migrations; the
// memory adapter has no catalog by default. Not part of any port.
func (r *AccountRepository) AddPlan(p domain.Plan) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.plans == nil {
		r.plans = make(map[string]*domain.Plan)
	}
	plan := p
	r.plans[p.Code] = &plan
}

// FindPlanByCode returns the catalog row for code, or ErrCodeNotFound
// when no such plan exists. Codes are the Lago plan.code strings the
// login-ui plan picker submits — the two catalogs stay in lockstep.
func (r *AccountRepository) FindPlanByCode(_ context.Context, code string) (*domain.Plan, error) {
	if code == "" {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "plan code is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.plans[code]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "plan not found: "+code)
	}
	out := *p
	return &out, nil
}

// ActivateAccountPlan attaches a plan to an account. Idempotent on
// (account_id, plan_id) — repeat calls return the existing active row
// with created=false. A different-plan active row surfaces as
// ErrCodeConflict; the application layer maps that to a 409 so the
// caller distinguishes "already provisioned" from a plan-change
// attempt (out of scope for E5-S2).
//
// The memory implementation also mirrors the activation into activePlan
// so ListByUserID reports the joined plan without any test-side setup.
// This matches the postgres LEFT JOIN semantics — activation is
// immediately visible on the switcher read.
func (r *AccountRepository) ActivateAccountPlan(_ context.Context, in ports.ActivateAccountPlanInput) (*domain.AccountPlan, bool, error) {
	if err := validateActivateInput(in); err != nil {
		return nil, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.accountPlans[in.AccountID]; ok {
		if existing.PlanID != in.PlanID {
			return nil, false, apperrors.New(apperrors.ErrCodeConflict,
				"account already has an active plan; plan change is not supported here")
		}
		out := *existing
		return &out, false, nil
	}
	id, err := newID()
	if err != nil {
		return nil, false, err
	}
	row := &domain.AccountPlan{
		ID:                 id,
		AccountID:          in.AccountID,
		PlanID:             in.PlanID,
		ValidFrom:          in.ValidFrom,
		LagoSubscriptionID: in.LagoSubscriptionID,
		CreatedAt:          in.ValidFrom,
		UpdatedAt:          in.ValidFrom,
	}
	if r.accountPlans == nil {
		r.accountPlans = make(map[string]*domain.AccountPlan)
	}
	r.accountPlans[in.AccountID] = row
	r.mirrorActivePlanLocked(in.AccountID, in.PlanID)
	out := *row
	return &out, true, nil
}

// mirrorActivePlanLocked keeps the memory adapter's ListByUserID join
// projection in sync with the account_plans state. Called under the
// mutex — do not acquire it again here. Silently noops when the plan
// is unknown, matching the postgres behaviour where a missing catalog
// row would have failed the FK before this method could run.
func (r *AccountRepository) mirrorActivePlanLocked(accountID, planID string) {
	if r.activePlan == nil {
		r.activePlan = make(map[string]domain.PlanSummary)
	}
	for _, p := range r.plans {
		if p.ID == planID {
			r.activePlan[accountID] = domain.PlanSummary{
				ID:          p.ID,
				Code:        p.Code,
				DisplayName: p.DisplayName,
			}
			return
		}
	}
}

// validateActivateInput enforces wire-boundary shape rules so
// ActivateAccountPlan never inserts a row with an empty FK.
func validateActivateInput(in ports.ActivateAccountPlanInput) error {
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
