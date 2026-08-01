// Package domain holds the entitlements-service business types and
// invariants. It depends on nothing outside the standard library — the
// entitlement rules must be reasonable about in isolation from any
// adapter (HTTP, Postgres, etc.). See ADR-0028 for the model rationale.
package domain

import "time"

// Role names for account_seats. Kept as a typed string so mistyped roles
// fail at compile time instead of at insert time; the schema also
// carries a CHECK constraint on the same set.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

// Valid reports whether r is one of the accepted role values.
func (r Role) Valid() bool {
	switch r {
	case RoleOwner, RoleAdmin, RoleMember:
		return true
	default:
		return false
	}
}

// Account is the billing/entitlement unit — 1:1 with a Lago customer
// once LagoCustomerID is wired. UserID is set only for personal accounts
// (1:1 with a user); non-personal accounts (created via invite/admin)
// leave it empty.
type Account struct {
	ID             string
	DisplayName    string
	BillingEmail   string
	UserID         string // "" for non-personal accounts
	LagoCustomerID string // "" until Lago is wired
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// IsPersonal reports whether this account is a personal account
// (1:1 with a user).
func (a Account) IsPersonal() bool {
	return a.UserID != ""
}

// Seat is a member's presence on an account. UserID is an opaque
// reference to identity-service — this service does not own the user
// record.
type Seat struct {
	ID        string
	AccountID string
	UserID    string
	Role      Role
	CreatedAt time.Time
	UpdatedAt time.Time
}

// PlanSummary is the projection of a Plan used inline in a
// UserSeatSummary. Not a subset of the full Plan record — carries only
// the fields the login-ui account switcher needs to label a row
// ("Personal (Free)" / "Touchline Club"). Adding more plan detail here
// is a UserSeatSummary-side concern; the plan catalog owns the rest.
type PlanSummary struct {
	ID          string
	Code        string
	DisplayName string
}

// UserSeatSummary is the per-seat row returned by
// SeatRepository.ListByUserID — the join of account_seats × accounts ×
// active account_plans × plans that the login-ui switcher consumes
// (E7-S3b). Plan is nil when the account has no currently-active plan
// (fresh account before checkout, or a lapsed subscription).
type UserSeatSummary struct {
	SeatID             string
	AccountID          string
	AccountDisplayName string
	Role               Role
	Plan               *PlanSummary
}
