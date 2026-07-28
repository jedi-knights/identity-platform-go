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
// orchestrates personal-account creation on user signup (E7-S1b) and
// emits the account_created audit event per ADR-0018 + ADR-0019.
type AccountService struct {
	repo    ports.AccountRepository
	emitter audit.Emitter
	service string
}

// NewAccountService constructs an AccountService with a no-op audit
// emitter. Wire a real emitter via WithAudit at the composition root.
func NewAccountService(repo ports.AccountRepository) *AccountService {
	if repo == nil {
		panic("application: NewAccountService called with nil repo")
	}
	return &AccountService{
		repo:    repo,
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
