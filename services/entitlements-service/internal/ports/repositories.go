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
}
