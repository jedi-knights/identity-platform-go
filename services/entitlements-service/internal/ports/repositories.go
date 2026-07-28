// Package ports declares the interfaces the entitlements-service
// application layer depends on. Adapters (inbound HTTP, outbound
// memory/postgres) satisfy these interfaces so the application layer
// can be tested and swapped without touching business logic.
package ports

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

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
