package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/ports"
)

var _ ports.InviteRepository = (*InviteRepository)(nil)

// InviteRepository is the in-memory implementation of the invite port.
// Safe for concurrent use — a single mutex guards the whole store
// because Insert must check the no-dup-open invariant atomically.
type InviteRepository struct {
	mu      sync.Mutex
	invites map[string]*domain.Invite // keyed by invite ID
}

// NewInviteRepository returns an empty in-memory invite repository.
func NewInviteRepository() *InviteRepository {
	return &InviteRepository{invites: make(map[string]*domain.Invite)}
}

// Insert persists inv with a generated ID and CreatedAt. Enforces the
// no-duplicate-open invariant: another invite for the same
// (account_id, invited_email) that is still pending (not accepted, not
// revoked) causes a conflict-flavored error so the caller can surface
// it as a 409 to the operator.
func (r *InviteRepository) Insert(_ context.Context, inv domain.Invite) (*domain.Invite, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	for _, existing := range r.invites {
		if existing.AccountID != inv.AccountID || existing.InvitedEmail != inv.InvitedEmail {
			continue
		}
		if existing.AcceptedAt == nil && existing.RevokedAt == nil {
			return nil, apperrors.New(apperrors.ErrCodeConflict,
				"an open invite for this email already exists on the account")
		}
	}
	id, err := newID()
	if err != nil {
		return nil, fmt.Errorf("generating invite id: %w", err)
	}
	stored := &domain.Invite{
		ID:              id,
		AccountID:       inv.AccountID,
		InvitedBySeatID: inv.InvitedBySeatID,
		InvitedEmail:    inv.InvitedEmail,
		TokenHash:       inv.TokenHash,
		ExpiresAt:       inv.ExpiresAt,
		AcceptedAt:      inv.AcceptedAt,
		RevokedAt:       inv.RevokedAt,
		CreatedAt:       now,
	}
	r.invites[id] = stored
	// Return a copy so callers cannot mutate our internal record via
	// the returned pointer. RawToken lives on the returned value only
	// — the caller (application service) forwards it to the email
	// adapter; the persisted row never carries it.
	out := *stored
	out.RawToken = inv.RawToken
	return &out, nil
}

// CountOpen counts invites on accountID that are pending — not
// accepted, not revoked, and not past their expiry.
func (r *InviteRepository) CountOpen(_ context.Context, accountID string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	var n int
	for _, inv := range r.invites {
		if inv.AccountID != accountID {
			continue
		}
		if inv.IsOpen(now) {
			n++
		}
	}
	return n, nil
}
