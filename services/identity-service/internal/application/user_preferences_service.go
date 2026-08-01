package application

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// UserPreferencesService is the E7-S3a use case: read and write the
// per-user "active account" preference identity-service owns. Emits a
// user_active_account_changed audit event when the effective value
// changes; a PUT that repeats the current value is silent (still succeeds
// at the HTTP layer, still refreshes UpdatedAt, but does not emit).
//
// Per ADR-0019 audit events on the user-state hot path are treated as
// paid — a durable-sink failure surfaces to the caller so the meter
// cannot have gaps.
//
// The service does NOT cross-check the referenced account against
// entitlements-service's account_seats table. That validation lives on
// the JWT-issuance path in E7-S3c; keeping identity-service off the
// outbound entitlements dependency on preference reads keeps the
// per-request fanout small.
type UserPreferencesService struct {
	repo    domain.UserPreferencesRepository
	emitter audit.Emitter
	service string
	now     func() time.Time
}

// NewUserPreferencesService constructs a UserPreferencesService with the
// given repository. The returned service uses a no-op audit emitter;
// call [UserPreferencesService.WithAudit] at the composition root to
// wire the real emitter.
func NewUserPreferencesService(repo domain.UserPreferencesRepository) *UserPreferencesService {
	if repo == nil {
		panic("application: NewUserPreferencesService called with nil repository")
	}
	return &UserPreferencesService{
		repo:    repo,
		emitter: audit.New(audit.NoopSink{}),
		service: "identity-service",
		now:     time.Now,
	}
}

// WithAudit configures the service's audit emitter and service name.
// emitter must be non-nil. Returns the receiver for chained construction.
func (s *UserPreferencesService) WithAudit(emitter audit.Emitter, service string) *UserPreferencesService {
	if emitter == nil {
		panic("application: WithAudit called with nil emitter")
	}
	s.emitter = emitter
	if service != "" {
		s.service = service
	}
	return s
}

// WithClock overrides the time source. Intended for tests — production
// always uses time.Now. Nil is rejected so a caller cannot silently
// disable timestamping.
func (s *UserPreferencesService) WithClock(now func() time.Time) *UserPreferencesService {
	if now == nil {
		panic("application: WithClock called with nil clock")
	}
	s.now = now
	return s
}

// GetActiveAccount returns the currently selected account for userID, or
// the empty string when the user has no preferences row (has not yet
// selected an account).
func (s *UserPreferencesService) GetActiveAccount(ctx context.Context, userID string) (string, error) {
	if strings.TrimSpace(userID) == "" {
		return "", apperrors.New(apperrors.ErrCodeBadRequest, "user id is required")
	}
	prefs, err := s.repo.Get(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("fetching user preferences: %w", err)
	}
	if prefs == nil {
		return "", nil
	}
	return prefs.ActiveAccountID, nil
}

// SetActiveAccount upserts the ActiveAccountID for userID. accountID must
// be non-empty (clearing is not supported today).
//
// A user_active_account_changed audit event is emitted only when the
// stored value transitions to a different accountID — a PUT that repeats
// the current value succeeds silently. The audit event carries the old
// and new account IDs so a downstream reader can reconstruct the transition
// without a state-diff.
func (s *UserPreferencesService) SetActiveAccount(ctx context.Context, userID, accountID string) error {
	if strings.TrimSpace(userID) == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "user id is required")
	}
	if strings.TrimSpace(accountID) == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "account id is required")
	}
	previous, err := s.repo.Get(ctx, userID)
	if err != nil {
		return fmt.Errorf("fetching user preferences: %w", err)
	}
	if err := s.repo.SetActiveAccount(ctx, userID, accountID, s.now()); err != nil {
		return fmt.Errorf("saving user preferences: %w", err)
	}
	previousID := ""
	if previous != nil {
		previousID = previous.ActiveAccountID
	}
	if previousID == accountID {
		return nil
	}
	return s.emitActiveAccountChanged(ctx, userID, previousID, accountID)
}

// emitActiveAccountChanged emits the ADR-0018 user_active_account_changed
// event. Failures surface to the caller per ADR-0019.
func (s *UserPreferencesService) emitActiveAccountChanged(ctx context.Context, userID, previousID, newID string) error {
	if err := s.emitter.Emit(ctx, audit.Event{
		EventType:      "user_active_account_changed",
		Service:        s.service,
		ActorType:      audit.ActorTypeUser,
		ActorID:        userID,
		SubjectID:      userID,
		Resource:       "endpoint:set_active_account",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "set_active_account",
		ResourceParent: s.service,
		ResourcePath:   s.service + "/endpoint/set_active_account",
		Action:         "set_active_account",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"previous_account_id": previousID,
			"new_account_id":      newID,
		},
	}); err != nil {
		return fmt.Errorf("audit emit (user_active_account_changed): %w", err)
	}
	return nil
}
