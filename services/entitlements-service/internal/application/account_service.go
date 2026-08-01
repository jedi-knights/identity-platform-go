// Package application holds the entitlements-service use-case
// services. Depends only on domain types and port interfaces — no HTTP,
// no SQL, no framework concerns. Hexagonal architecture per ADR-0001.
package application

import (
	"context"
	"fmt"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/ports"
)

// AccountService is the entitlements-service account use-case. It
// orchestrates personal-account creation on user signup (E7-S1b),
// exposes the switcher-list read (E7-S3b), and emits the
// account_created audit event per ADR-0018 + ADR-0019.
type AccountService struct {
	repo    ports.AccountRepository
	seats   ports.SeatRepository
	emitter audit.Emitter
	service string
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
		repo:    repo,
		seats:   seats,
		emitter: audit.New(audit.NoopSink{}),
		service: "entitlements-service",
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
