// Package application holds the entitlements-service use-case
// services. Depends only on domain types and port interfaces — no HTTP,
// no SQL, no framework concerns. Hexagonal architecture per ADR-0001.
package application

import (
	"context"
	"fmt"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/ports"
)

// DefaultTransferOwnershipMaxAuthAge is the freshness ceiling on the
// requester's most-recent-authentication timestamp for the E7-S5
// transfer-ownership flow. Matches the AC on issue #173 ("fresh login
// within 5 min"). Overridable at composition time via
// [AccountService.WithTransferOwnershipMaxAuthAge].
const DefaultTransferOwnershipMaxAuthAge = 5 * time.Minute

// AccountService is the entitlements-service account use-case. It
// orchestrates personal-account creation on user signup (E7-S1b),
// exposes the switcher-list read (E7-S3b), the seat-removal use case
// (E7-S4), the ownership-transfer flow (E7-S5), the plan-activation
// flow (E5-S2), and emits ADR-0018 audit events per ADR-0019.
type AccountService struct {
	repo    ports.AccountRepository
	seats   ports.SeatRepository
	plans   ports.PlanRepository
	emitter audit.Emitter
	service string
	// transferMaxAuthAge is the fresh-authentication ceiling the
	// TransferOwnership pre-check enforces (E7-S5 AC). Zero disables
	// the check — reserved for tests that need to bypass the freshness
	// gate without racing a real clock.
	transferMaxAuthAge time.Duration
	// now is the time source the TransferOwnership freshness check
	// reads. Overridable in tests via WithClock so a fixed instant
	// pins auth-age arithmetic without sleep-based races.
	now func() time.Time
}

// NewAccountService constructs an AccountService with a no-op audit
// emitter. Wire a real emitter via WithAudit at the composition root.
// The account repository is expected to also satisfy SeatRepository —
// the memory and postgres adapters both do so, mirroring the
// InviteService constructor's rationale.
func NewAccountService(repo ports.AccountRepository) *AccountService {
	if repo == nil {
		panic("application: NewAccountService called with nil repo")
	}
	seats, ok := repo.(ports.SeatRepository)
	if !ok {
		panic("application: NewAccountService requires repo to also satisfy SeatRepository")
	}
	return &AccountService{
		repo:               repo,
		seats:              seats,
		emitter:            audit.New(audit.NoopSink{}),
		service:            "entitlements-service",
		transferMaxAuthAge: DefaultTransferOwnershipMaxAuthAge,
		now:                time.Now,
	}
}

// WithAudit configures the service's audit emitter. emitter must be
// non-nil. Returns the receiver to allow chained construction.
func (s *AccountService) WithAudit(emitter audit.Emitter, service string) *AccountService {
	if emitter == nil {
		panic("application: WithAudit called with nil emitter")
	}
	s.emitter = emitter
	if service != "" {
		s.service = service
	}
	return s
}

// WithTransferOwnershipMaxAuthAge overrides the freshness ceiling on
// the requester's most-recent-authentication timestamp for the
// TransferOwnership pre-check. Zero disables the check — reserved for
// tests that need to bypass the freshness gate without racing a real
// clock; production code must not pass zero.
func (s *AccountService) WithTransferOwnershipMaxAuthAge(d time.Duration) *AccountService {
	s.transferMaxAuthAge = d
	return s
}

// WithClock overrides the time source used by the TransferOwnership
// freshness check. Intended for tests — production always uses
// time.Now. Nil is rejected so a caller cannot silently disable
// timestamping.
func (s *AccountService) WithClock(now func() time.Time) *AccountService {
	if now == nil {
		panic("application: WithClock called with nil clock")
	}
	s.now = now
	return s
}

// CreatePersonalAccount creates a personal account for userID if none
// exists, or returns the existing account otherwise. Idempotent on
// userID — safe for identity-service to call once per signup and again
// on any retry.
//
// The returned created bool is true only when this call actually
// created the account; a subsequent idempotent call returns false so
// the adapter can distinguish 201 from 200 without a timestamp sniff.
//
// The account_created audit event is emitted only on the create path
// (created == true). Emit failures surface to the caller so the
// sign-up request fails and the operator sees the audit gap — the
// event is paid per ADR-0019 (it triggers downstream Lago customer
// creation).
func (s *AccountService) CreatePersonalAccount(ctx context.Context, userID, email string) (acc *domain.Account, created bool, err error) {
	if err := validatePersonalAccountInput(userID, email); err != nil {
		return nil, false, err
	}
	existing, err := s.repo.FindByUserID(ctx, userID)
	if err != nil && !apperrors.IsNotFound(err) {
		return nil, false, fmt.Errorf("looking up personal account for %q: %w", userID, err)
	}
	if existing != nil {
		return existing, false, nil
	}
	acc, err = s.repo.UpsertPersonalAccount(ctx, userID, email)
	if err != nil {
		return nil, false, fmt.Errorf("upserting personal account for %q: %w", userID, err)
	}
	if err := s.emitAccountCreated(ctx, acc); err != nil {
		return nil, false, err
	}
	return acc, true, nil
}

// ListUserSeats returns every account seat userID occupies, joined
// with the account display name and (if any) the currently-active plan
// summary. Empty slice (nil error) for a user with no seats — the
// switcher UI treats that as "prompt to create/join an account", not
// as an error. No audit emission: list operations are unpaid per
// ADR-0019.
func (s *AccountService) ListUserSeats(ctx context.Context, userID string) ([]domain.UserSeatSummary, error) {
	if userID == "" {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "user_id is required")
	}
	rows, err := s.seats.ListByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("listing user seats for %q: %w", userID, err)
	}
	return rows, nil
}

// TransferOwnershipRequest is the shape the HTTP handler forwards
// to TransferOwnership. RequesterAuthTime carries the moment the
// requester most recently completed a fresh authentication — used
// to enforce the E7-S5 AC's 5-minute freshness ceiling. Today that
// value comes from an X-Requester-Auth-Time header; once
// auth-server's JWT integration into entitlements-service lands, it
// will come from the token's auth_time claim.
type TransferOwnershipRequest struct {
	AccountID         string
	RequesterUserID   string
	RequesterAuthTime time.Time
	TargetUserID      string
}

// TransferOwnership is the E7-S5 use case: the current owner-role
// seat hands ownership to another seat on the same account. Emits an
// ownership_transferred audit event per ADR-0018 + ADR-0019.
//
// Business rules enforced here, in order:
//   - Input validation (400)
//   - Fresh-auth guard: requester's last authentication must be no
//     older than transferMaxAuthAge (403). See the field docstring
//     for how this bridges to a real auth_time claim later.
//   - Requester must currently be an owner-role seat on the account
//     (403 — collapses "not a seat" and "wrong role" so the API does
//     not disclose membership).
//   - Target user must be an existing seat on the account (404). Not
//     an owner-elsewhere check — the target could be a member on
//     this account and an owner on a different one; that is fine.
//   - Same-user transfer is refused (400 — a promotion loop is a
//     programming error, not a policy). AC #173 does not mention it;
//     surfacing it early avoids a spurious audit event.
//
// Then the atomic swap runs (repo enforces atomicity), and finally
// the audit event fires. Audit failure surfaces to the caller.
func (s *AccountService) TransferOwnership(ctx context.Context, req TransferOwnershipRequest) error {
	if err := s.preflightTransfer(ctx, req); err != nil {
		return err
	}
	if err := s.seats.SwapOwner(ctx, req.AccountID, req.RequesterUserID, req.TargetUserID); err != nil {
		return fmt.Errorf("swap owner: %w", err)
	}
	return s.emitOwnershipTransferred(ctx, req)
}

// preflightTransfer runs the pre-swap validation and RBAC pipeline.
// Extracted so TransferOwnership's cyclomatic complexity stays within
// the gocyclo budget while covering every business-rule branch.
func (s *AccountService) preflightTransfer(ctx context.Context, req TransferOwnershipRequest) error {
	if err := validateTransferInput(req); err != nil {
		return err
	}
	if req.RequesterUserID == req.TargetUserID {
		return apperrors.New(apperrors.ErrCodeBadRequest, "requester and target must differ")
	}
	if err := s.assertFreshAuth(req.RequesterAuthTime); err != nil {
		return err
	}
	if err := s.assertRequesterIsOwner(ctx, req.AccountID, req.RequesterUserID); err != nil {
		return err
	}
	return s.assertTargetSeatExists(ctx, req.AccountID, req.TargetUserID)
}

// assertTargetSeatExists confirms the transfer target already occupies
// a seat on the account. The AC on issue #173 requires this — you can
// only promote an existing member to owner, never invite-and-promote
// in one step.
func (s *AccountService) assertTargetSeatExists(ctx context.Context, accountID, targetUserID string) error {
	if _, err := s.seats.FindSeat(ctx, accountID, targetUserID); err != nil {
		if apperrors.IsNotFound(err) {
			return apperrors.New(apperrors.ErrCodeNotFound, "target seat not found on this account")
		}
		return fmt.Errorf("looking up target seat: %w", err)
	}
	return nil
}

// validateTransferInput enforces the wire-boundary shape rules so
// TransferOwnership stays under the gocyclo cap alongside the RBAC
// and freshness branches.
func validateTransferInput(req TransferOwnershipRequest) error {
	if req.AccountID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "account_id is required")
	}
	if req.RequesterUserID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "requester user_id is required")
	}
	if req.TargetUserID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "target user_id is required")
	}
	if req.RequesterAuthTime.IsZero() {
		return apperrors.New(apperrors.ErrCodeBadRequest, "requester auth_time is required")
	}
	return nil
}

// assertFreshAuth surfaces the E7-S5 5-minute step-up-auth guard. A
// zero transferMaxAuthAge disables the check (test-only escape).
// Requesters whose auth stamp is in the future by more than one
// second surface as bad-request — a real caller would never present
// this, but a bug in whichever service forwards the header could
// otherwise silently bypass the check.
func (s *AccountService) assertFreshAuth(authTime time.Time) error {
	if s.transferMaxAuthAge <= 0 {
		return nil
	}
	now := s.now()
	if authTime.After(now.Add(time.Second)) {
		return apperrors.New(apperrors.ErrCodeBadRequest, "requester auth_time is in the future")
	}
	if now.Sub(authTime) > s.transferMaxAuthAge {
		return apperrors.New(apperrors.ErrCodeForbidden,
			"re-authentication required (fresh login within 5 min)")
	}
	return nil
}

// emitOwnershipTransferred emits the ADR-0018 ownership_transferred
// event. Actor is the requester (previous owner); subject is the
// target (new owner). Attrs carry both parties + account_id so a
// post-hoc reader can reconstruct the swap without a state diff.
func (s *AccountService) emitOwnershipTransferred(ctx context.Context, req TransferOwnershipRequest) error {
	if err := s.emitter.Emit(ctx, audit.Event{
		EventType:      "ownership_transferred",
		Service:        s.service,
		ActorType:      audit.ActorTypeUser,
		ActorID:        req.RequesterUserID,
		SubjectID:      req.TargetUserID,
		Resource:       "endpoint:accounts.transfer_ownership",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "accounts.transfer_ownership",
		ResourceParent: s.service,
		ResourcePath:   s.service + "/endpoint/accounts.transfer_ownership",
		Action:         "transfer_ownership",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"account_id":        req.AccountID,
			"previous_owner_id": req.RequesterUserID,
			"new_owner_id":      req.TargetUserID,
		},
	}); err != nil {
		return fmt.Errorf("audit emit (ownership_transferred): %w", err)
	}
	return nil
}

// RemoveSeatRequest is the shape the HTTP handler forwards to
// RemoveSeat. RequesterUserID comes from the request's authentication
// context — today an X-Requester-User-ID header; JWT claims when
// auth-server's token integration into entitlements-service lands.
type RemoveSeatRequest struct {
	AccountID       string
	RequesterUserID string
	TargetUserID    string
}

// RemoveSeat is the E7-S4 use case: an owner-role seat removes another
// seat from an account. Emits a seat_removed audit event per
// ADR-0018 + ADR-0019 — paid event since seat count changes drive
// downstream Lago subscription sync.
//
// Business rules enforced here:
//   - Requester must be an owner-role seat on the account (403).
//   - Owner cannot remove themselves — a solo owner has nobody to
//     transfer to yet; a co-owner departure runs through E7-S5's
//     transfer flow first (409 with "must transfer ownership first").
//   - Target seat must exist on the account (404).
//
// Note the deliberate absence of a "last-owner" check when removing a
// co-owner: the AC on issue #172 mentions only self-removal. If the
// operator sets up two owners and one removes the other, that is
// allowed — the remaining owner is fully accountable.
func (s *AccountService) RemoveSeat(ctx context.Context, req RemoveSeatRequest) error {
	if err := validateRemoveSeatInput(req); err != nil {
		return err
	}
	if req.RequesterUserID == req.TargetUserID {
		return apperrors.New(apperrors.ErrCodeConflict,
			"owners cannot remove themselves; transfer ownership first")
	}
	if err := s.assertRequesterIsOwner(ctx, req.AccountID, req.RequesterUserID); err != nil {
		return err
	}
	target, err := s.seats.FindSeat(ctx, req.AccountID, req.TargetUserID)
	if err != nil {
		if apperrors.IsNotFound(err) {
			return apperrors.New(apperrors.ErrCodeNotFound, "seat not found on this account")
		}
		return fmt.Errorf("looking up target seat: %w", err)
	}
	if err := s.seats.Remove(ctx, req.AccountID, req.TargetUserID); err != nil {
		return fmt.Errorf("removing seat: %w", err)
	}
	return s.emitSeatRemoved(ctx, req, target)
}

// validateRemoveSeatInput enforces the wire-boundary shape rules so
// RemoveSeat never inspects empty inputs. Extracted to keep RemoveSeat
// under the gocyclo cap alongside the RBAC + self-remove branches.
func validateRemoveSeatInput(req RemoveSeatRequest) error {
	if req.AccountID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "account_id is required")
	}
	if req.RequesterUserID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "requester user_id is required")
	}
	if req.TargetUserID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "target user_id is required")
	}
	return nil
}

// assertRequesterIsOwner confirms the requester holds an owner-role
// seat on the account. Returns 403 for any other role and 404 when
// the account itself has no seat for the requester (the requester is
// not a member) — both collapse to a client-safe "forbidden" at the
// HTTP boundary so the API does not disclose membership.
func (s *AccountService) assertRequesterIsOwner(ctx context.Context, accountID, requesterUserID string) error {
	seat, err := s.seats.FindSeat(ctx, accountID, requesterUserID)
	if err != nil {
		if apperrors.IsNotFound(err) {
			return apperrors.New(apperrors.ErrCodeForbidden, "requester is not a seat on this account")
		}
		return fmt.Errorf("looking up requester seat: %w", err)
	}
	if seat.Role != domain.RoleOwner {
		return apperrors.New(apperrors.ErrCodeForbidden, "only owners can remove seats")
	}
	return nil
}

// emitSeatRemoved emits the ADR-0018 seat_removed event. Actor is the
// requester (who took the action); subject is the removed user. Attrs
// carry the account_id + the role that was removed for post-hoc
// forensics ("did we lose our second owner?").
func (s *AccountService) emitSeatRemoved(ctx context.Context, req RemoveSeatRequest, removed *domain.Seat) error {
	if err := s.emitter.Emit(ctx, audit.Event{
		EventType:      "seat_removed",
		Service:        s.service,
		ActorType:      audit.ActorTypeUser,
		ActorID:        req.RequesterUserID,
		SubjectID:      req.TargetUserID,
		Resource:       "endpoint:accounts.seats.remove",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "accounts.seats.remove",
		ResourceParent: s.service,
		ResourcePath:   s.service + "/endpoint/accounts.seats.remove",
		Action:         "remove_seat",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"account_id":   req.AccountID,
			"removed_role": string(removed.Role),
			"seat_id":      removed.ID,
		},
	}); err != nil {
		return fmt.Errorf("audit emit (seat_removed): %w", err)
	}
	return nil
}

// validatePersonalAccountInput enforces the wire-boundary shape rules
// so CreatePersonalAccount never inspects empty inputs. Extracted so
// the entry point stays under the gocyclo budget.
func validatePersonalAccountInput(userID, email string) error {
	if userID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "user_id is required")
	}
	if email == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "email is required")
	}
	return nil
}

// WithPlans wires the plan repository so the ActivatePlan use case can
// resolve plan_code → plan_id and write account_plans. Nil is rejected
// so a mis-composed container fails loudly at startup rather than at
// the first plan-selection request.
func (s *AccountService) WithPlans(plans ports.PlanRepository) *AccountService {
	if plans == nil {
		panic("application: WithPlans called with nil plans repository")
	}
	s.plans = plans
	return s
}

// ActivatePlanRequest is the shape the HTTP handler forwards to
// ActivatePlan. LagoSubscriptionID is empty on the free-plan path;
// paid plans carry the subscription identifier Lago handed back so
// downstream reconciliation can join account_plans × Lago.
type ActivatePlanRequest struct {
	AccountID          string
	PlanCode           string
	LagoSubscriptionID string
}

// ActivatePlan is the E5-S2 use case: the login-ui plan picker has
// converged on a plan and Lago has recorded the customer/subscription
// pair; entitlements-service now writes the account_plans row so the
// switcher, seat-allowance, and MCP-gating reads all reflect the
// chosen plan.
//
// Idempotent on (account_id, plan_code): a replay returns the existing
// row with created=false and no duplicate audit event. A different-plan
// active row surfaces as ErrCodeConflict (409) — plan changes route
// through a distinct future endpoint.
//
// The plan_activated audit event fires only on the create path so a
// replayed provisioning call does not double-count. Emit failure
// surfaces to the caller — the login-ui composite backs off and retries,
// which is the correct behaviour when the audit sink is momentarily
// unavailable.
func (s *AccountService) ActivatePlan(ctx context.Context, req ActivatePlanRequest) (*domain.AccountPlan, bool, error) {
	if s.plans == nil {
		return nil, false, apperrors.New(apperrors.ErrCodeInternal, "plan repository not configured")
	}
	if err := validateActivatePlanInput(req); err != nil {
		return nil, false, err
	}
	plan, err := s.plans.FindPlanByCode(ctx, req.PlanCode)
	if err != nil {
		return nil, false, fmt.Errorf("resolving plan code %q: %w", req.PlanCode, err)
	}
	row, created, err := s.plans.ActivateAccountPlan(ctx, ports.ActivateAccountPlanInput{
		AccountID:          req.AccountID,
		PlanID:             plan.ID,
		LagoSubscriptionID: req.LagoSubscriptionID,
		ValidFrom:          s.now(),
	})
	if err != nil {
		return nil, false, fmt.Errorf("activating account plan: %w", err)
	}
	if created {
		if err := s.emitPlanActivated(ctx, row, plan); err != nil {
			return nil, false, err
		}
	}
	return row, created, nil
}

// validateActivatePlanInput enforces wire-boundary shape rules.
// Extracted so ActivatePlan stays under the gocyclo budget.
func validateActivatePlanInput(req ActivatePlanRequest) error {
	if req.AccountID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "account_id is required")
	}
	if req.PlanCode == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "plan_code is required")
	}
	return nil
}

// emitPlanActivated emits the ADR-0018 plan_activated event. Actor is
// the account (subject_id) since the acting principal at this hop is
// the login-ui service; the account is the thing being modified. Attrs
// carry plan_code + tier so a post-hoc reader can price the tier
// distribution without joining plans.
func (s *AccountService) emitPlanActivated(ctx context.Context, row *domain.AccountPlan, plan *domain.Plan) error {
	if err := s.emitter.Emit(ctx, audit.Event{
		EventType:      "plan_activated",
		Service:        s.service,
		ActorType:      audit.ActorTypeService,
		ActorID:        s.service,
		SubjectID:      row.AccountID,
		Resource:       "endpoint:accounts.plans",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "accounts.plans",
		ResourceParent: s.service,
		ResourcePath:   s.service + "/endpoint/accounts.plans",
		Action:         "activate_plan",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"account_id":           row.AccountID,
			"plan_id":              row.PlanID,
			"plan_code":            plan.Code,
			"plan_tier":            plan.Tier,
			"lago_subscription_id": row.LagoSubscriptionID,
		},
	}); err != nil {
		return fmt.Errorf("audit emit (plan_activated): %w", err)
	}
	return nil
}

// emitAccountCreated emits the ADR-0018 account_created event. Follows
// the E4 audit-fixtures pattern — every resource-taxonomy field
// populated so downstream metering can route on route-level provenance.
func (s *AccountService) emitAccountCreated(ctx context.Context, acc *domain.Account) error {
	if err := s.emitter.Emit(ctx, audit.Event{
		EventType:      "account_created",
		Service:        s.service,
		ActorType:      audit.ActorTypeUser,
		ActorID:        acc.UserID,
		SubjectID:      acc.ID,
		Resource:       "endpoint:accounts.personal",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "accounts.personal",
		ResourceParent: s.service,
		ResourcePath:   s.service + "/endpoint/accounts.personal",
		Action:         "create",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"billing_email": acc.BillingEmail,
			"personal":      true,
		},
	}); err != nil {
		return fmt.Errorf("audit emit (account_created): %w", err)
	}
	return nil
}
