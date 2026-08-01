package domain

import (
	"context"
	"time"
)

// UserPreferences carries the mutable per-user preferences identity-service
// owns. Today the only field is ActiveAccountID (the entitlements-service
// account the user has currently selected as their working context, per
// Epic 7 multi-seat). The type is defined as a struct rather than a bare
// string so future preferences (timezone, locale, notification settings)
// can join without another storage layer.
//
// ActiveAccountID is an opaque reference to entitlements-service — the
// authoritative table (account_seats) lives there. identity-service does
// not validate that the referenced account exists or that the user has a
// seat on it; that check lives on the JWT-issuance path in E7-S3c, where
// auth-server can reject a stale preference at token time. Storing the raw
// string here keeps identity-service free of an outbound entitlements
// dependency on the read-preference hot path.
type UserPreferences struct {
	UserID          string
	ActiveAccountID string
	UpdatedAt       time.Time
}

// UserPreferencesRepository defines persistence operations for a user's
// per-user preferences.
//
// Get returns (nil, nil) when the user has no preferences row yet — the
// user exists but has never set an active account. Callers distinguish
// "never chosen" (nil) from "chosen and empty" (a row with ActiveAccountID
// == "") because the latter is not a valid state today (SetActiveAccount
// rejects empty values), but leaving the door open costs nothing.
type UserPreferencesRepository interface {
	// Get returns the preferences row for userID, or (nil, nil) when the
	// user has no preferences yet.
	Get(ctx context.Context, userID string) (*UserPreferences, error)

	// SetActiveAccount upserts the ActiveAccountID for userID, stamping
	// UpdatedAt to `now`. When the row does not exist it is created;
	// when it does exist it is updated atomically.
	//
	// Returns a not-found error when userID does not exist in the users
	// table — the FK constraint enforces this at the storage layer.
	SetActiveAccount(ctx context.Context, userID, accountID string, now time.Time) error
}
