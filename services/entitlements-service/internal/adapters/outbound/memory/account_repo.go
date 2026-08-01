// Package memory holds in-memory implementations of the
// entitlements-service outbound ports. Default adapter per repo
// convention — the Postgres adapter is swapped in via container.go
// when ENTITLEMENTS_DB_URL is set. See ADR-0004 in the identity
// platform for the reference-implementation stance on in-memory
// persistence.
package memory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/ports"
)

// Compile-time assertions that AccountRepository satisfies both
// interfaces. These mark the swap point for the Postgres adapter and
// catch interface drift at declaration site.
var (
	_ ports.AccountRepository = (*AccountRepository)(nil)
	_ ports.SeatRepository    = (*AccountRepository)(nil)
)

// AccountRepository is the in-memory implementation of the
// entitlements-service account + seat repository. Safe for concurrent
// use — a single RWMutex guards both maps because personal-account
// upsert must lock across the account-lookup + seat-create sequence.
type AccountRepository struct {
	mu       sync.Mutex
	accounts map[string]*domain.Account // keyed by account ID
	byUser   map[string]string          // user_id -> account ID (personal accounts only)
	seats    map[string][]domain.Seat   // account ID -> seats
	// allowanceOverride is a test-only escape hatch for
	// SetSeatAllowance. Not persisted, not exposed via the port.
	allowanceOverride map[string]int
	// activePlan is a test-only mapping from account ID to a
	// PlanSummary that ListByUserID reports on the joined row. Real
	// plan attribution lives in Postgres (account_plans × plans); this
	// escape hatch lets memory-backed tests exercise the "account has
	// a plan" branch without a full catalog. Not part of any port.
	activePlan map[string]domain.PlanSummary
}

// NewAccountRepository returns an empty in-memory account repository.
func NewAccountRepository() *AccountRepository {
	return &AccountRepository{
		accounts: make(map[string]*domain.Account),
		byUser:   make(map[string]string),
		seats:    make(map[string][]domain.Seat),
	}
}

// UpsertPersonalAccount creates or returns the personal account for
// userID. Concurrent calls with the same userID are serialised by the
// mutex so the second caller sees the first's insert.
func (r *AccountRepository) UpsertPersonalAccount(_ context.Context, userID, email string) (*domain.Account, error) {
	if userID == "" {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "user_id is required")
	}
	if email == "" {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "email is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existingID, ok := r.byUser[userID]; ok {
		return r.accounts[existingID], nil
	}
	now := time.Now().UTC()
	accountID, err := newID()
	if err != nil {
		return nil, fmt.Errorf("generating account id: %w", err)
	}
	seatID, err := newID()
	if err != nil {
		return nil, fmt.Errorf("generating seat id: %w", err)
	}
	acc := &domain.Account{
		ID:           accountID,
		DisplayName:  email, // personal accounts default to email as display
		BillingEmail: email,
		UserID:       userID,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	r.accounts[accountID] = acc
	r.byUser[userID] = accountID
	r.seats[accountID] = []domain.Seat{{
		ID:        seatID,
		AccountID: accountID,
		UserID:    userID,
		Role:      domain.RoleOwner,
		CreatedAt: now,
		UpdatedAt: now,
	}}
	return acc, nil
}

// FindByUserID returns the personal account owned by userID or a
// not-found error. Non-personal accounts (UserID = "") are unreachable
// through this method by design — they're located via the account ID
// path once other flows land.
func (r *AccountRepository) FindByUserID(_ context.Context, userID string) (*domain.Account, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	accountID, ok := r.byUser[userID]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "personal account not found for user "+userID)
	}
	return r.accounts[accountID], nil
}

// ListByAccount returns the seats attached to accountID. Empty slice
// (not an error) when accountID is unknown — callers can distinguish
// "no seats" from "no account" via a separate account lookup.
func (r *AccountRepository) ListByAccount(_ context.Context, accountID string) ([]domain.Seat, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seats := r.seats[accountID]
	// Return a copy so callers cannot mutate our internal slice.
	out := make([]domain.Seat, len(seats))
	copy(out, seats)
	return out, nil
}

// ListByUserID returns every seat userID occupies, joined with the
// seat's account display name and the account's active plan (if any).
// Ordering is by seat CreatedAt ascending — matches the postgres
// adapter and gives login-ui a stable listing.
//
// Memory has no real plan catalog; a row's Plan is populated only when
// a test has called SetActivePlan for that account (see the field
// docstring). Real plan attribution lives in the postgres adapter.
func (r *AccountRepository) ListByUserID(_ context.Context, userID string) ([]domain.UserSeatSummary, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var matches []domain.Seat
	for _, accountSeats := range r.seats {
		for _, s := range accountSeats {
			if s.UserID == userID {
				matches = append(matches, s)
			}
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].CreatedAt.Before(matches[j].CreatedAt)
	})

	out := make([]domain.UserSeatSummary, 0, len(matches))
	for _, s := range matches {
		acc, ok := r.accounts[s.AccountID]
		if !ok {
			// Orphan seat (should not happen; belt-and-braces).
			continue
		}
		row := domain.UserSeatSummary{
			SeatID:             s.ID,
			AccountID:          acc.ID,
			AccountDisplayName: acc.DisplayName,
			Role:               s.Role,
		}
		if plan, hasPlan := r.activePlan[acc.ID]; hasPlan {
			p := plan
			row.Plan = &p
		}
		out = append(out, row)
	}
	return out, nil
}

// SetActivePlan attaches a plan projection to accountID for tests that
// need to exercise the "account has a plan" branch of ListByUserID.
// Not part of any port; test-only helper mirroring SetSeatAllowance.
func (r *AccountRepository) SetActivePlan(accountID string, plan domain.PlanSummary) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.activePlan == nil {
		r.activePlan = make(map[string]domain.PlanSummary)
	}
	r.activePlan[accountID] = plan
}

// SeatAllowance returns the seat allowance for accountID's active plan.
// The in-memory adapter has no plan catalog (plans are held only in
// Postgres via the E3-S3 seed), so this returns the personal-account
// default of 1 unless a test has explicitly overridden it via
// SetSeatAllowance. Real plan lookups happen in the Postgres adapter.
func (r *AccountRepository) SeatAllowance(_ context.Context, accountID string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n, ok := r.allowanceOverride[accountID]; ok {
		return n, nil
	}
	return 1, nil
}

// SetSeatAllowance overrides the default in-memory allowance for
// accountID — for tests that need to exercise multi-seat paths without
// a real plan catalog. Not part of the port; test-only helper.
func (r *AccountRepository) SetSeatAllowance(accountID string, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.allowanceOverride == nil {
		r.allowanceOverride = make(map[string]int)
	}
	r.allowanceOverride[accountID] = n
}

// newID returns 16 hex-encoded random bytes (128 bits of entropy).
// Sourced from crypto/rand so IDs are unguessable — external systems
// (auth-server, Lago) join on these values.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}
