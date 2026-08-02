// Package ports declares the interfaces the entitlements-service
// application layer depends on. Adapters (inbound HTTP, outbound
// memory/postgres) satisfy these interfaces so the application layer
// can be tested and swapped without touching business logic.
package ports

import (
	"context"
	"time"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

// ActivateAccountPlanInput is the input shape for PlanRepository.
// ActivateAccountPlan. ValidFrom is passed in from the application layer
// (not defaulted at the adapter) so tests can pin a deterministic
// timestamp and the write matches the audit event's timestamp exactly.
type ActivateAccountPlanInput struct {
	AccountID          string
	PlanID             string
	LagoSubscriptionID string
	ValidFrom          time.Time
}

// PlanRepository reads the plan catalog and writes account_plans rows.
// The catalog is separate from AccountRepository because it has a
// distinct lifecycle — plans are edited by ops, accounts are created by
// users. Splitting the port lets memory-backed tests exercise plan
// activation without stubbing the seat surface.
type PlanRepository interface {
	// FindPlanByCode returns the plan row keyed by code (Lago plan.code)
	// or ErrCodeNotFound. Callers translate the plan_code the user
	// picked in login-ui into a plan_id for the account_plans FK.
	FindPlanByCode(ctx context.Context, code string) (*domain.Plan, error)

	// ActivateAccountPlan attaches a plan to an account. Idempotent by
	// (account_id, plan_id, valid_until IS NULL):
	//   - if an active row already exists for the same (account, plan),
	//     the existing row is returned with created=false.
	//   - if an active row exists for a *different* plan, ErrCodeConflict
	//     is returned — plan changes go through a distinct flow that
	//     closes the prior row first (out of scope for E5-S2).
	//   - otherwise the row is inserted and returned with created=true.
	ActivateAccountPlan(ctx context.Context, in ActivateAccountPlanInput) (*domain.AccountPlan, bool, error)
}

// AccountRepository persists Account rows and their owner Seat. The
// personal-account create path is expressed as a single upsert method
// (UpsertPersonalAccount) so the repository can enforce the
// account/owner-seat pair atomically — the account and its owner seat
// are created in one transaction, or neither is created.
type AccountRepository interface {
	// UpsertPersonalAccount creates a personal account for userID + email
	// if none exists, or returns the existing account if one does. The
	// owner Seat is created in the same transaction on the create path.
	//
	// Idempotency key is domain.Account.UserID. Two concurrent calls with
	// the same userID must return the same account.
	UpsertPersonalAccount(ctx context.Context, userID, email string) (*domain.Account, error)

	// FindByUserID returns the personal account owned by userID, or a
	// not-found error when none exists.
	FindByUserID(ctx context.Context, userID string) (*domain.Account, error)
}

// SeatRepository is broken out from AccountRepository so future
// non-personal invite/admin flows can add seats without needing the
// full account-upsert surface.
type SeatRepository interface {
	// ListByAccount returns every seat attached to accountID.
	ListByAccount(ctx context.Context, accountID string) ([]domain.Seat, error)

	// ListByUserID returns every account seat userID occupies, joined
	// against the seat's account and (LEFT JOIN) the account's currently-
	// active plan. Empty slice (nil error) when the user has no seats.
	// Ordered by seat created_at ascending so callers see a stable
	// listing across calls.
	//
	// The join is materialised at the repository so login-ui can render
	// the switcher in a single round-trip; the alternative (list seats,
	// then fan out per-account plan reads) doubles latency and multiplies
	// pool contention.
	ListByUserID(ctx context.Context, userID string) ([]domain.UserSeatSummary, error)

	// SeatAllowance returns the number of seats the account's active
	// plan permits. When the account has no active plan_bundles row
	// (typical for freshly-created personal accounts before checkout),
	// returns the default personal-account allowance of 1.
	//
	// Application-layer callers should treat "at allowance" as a
	// user-visible error (the invite / add-seat request is refused
	// with an "upgrade your plan" message), not an infrastructure
	// failure.
	SeatAllowance(ctx context.Context, accountID string) (int, error)

	// FindSeat returns the seat (accountID, userID) tuple identifies,
	// or a not-found error when no such row exists. Used by the
	// remove-seat authorisation path so the application layer can
	// distinguish "no such seat" (404) from "requester lacks the
	// role to remove it" (403).
	FindSeat(ctx context.Context, accountID, userID string) (*domain.Seat, error)

	// Remove deletes the seat (accountID, userID) identifies.
	// Returns a not-found error when no such seat exists — callers
	// should probe with FindSeat first when they need to distinguish
	// "already removed" from other failures.
	Remove(ctx context.Context, accountID, userID string) error

	// SwapOwner atomically demotes oldOwnerUserID from owner → admin
	// and promotes newOwnerUserID → owner within accountID. Both seats
	// must exist and oldOwnerUserID must currently be the owner —
	// implementations validate under the same lock/transaction that
	// performs the update so an interleaved probe cannot see one seat
	// updated without the other.
	//
	// Returns a not-found error when either seat is missing, and a
	// conflict error when oldOwnerUserID is not currently the owner
	// (application-layer callers surface both to the client — the
	// distinction is diagnostic, not policy-critical).
	SwapOwner(ctx context.Context, accountID, oldOwnerUserID, newOwnerUserID string) error
}

// InviteRepository persists account invites — the sending half of the
// invite flow (E7-S2). The accepting half lives in a follow-up story.
type InviteRepository interface {
	// Insert persists a new invite and returns it with its generated
	// ID and timestamps populated. inv.RawToken is not persisted —
	// the caller must have already hashed it into inv.TokenHash.
	Insert(ctx context.Context, inv domain.Invite) (*domain.Invite, error)

	// CountOpen returns the number of open (pending, not-expired) invites
	// on the account. Used by the seat-allowance check so an operator
	// cannot over-invite by racing multiple POSTs before anyone
	// accepts.
	CountOpen(ctx context.Context, accountID string) (int, error)
}
