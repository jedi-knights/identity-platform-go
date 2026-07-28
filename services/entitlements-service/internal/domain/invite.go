package domain

import "time"

// InviteStatus is the lifecycle state of an account invite. Derived
// from the row's accepted_at / revoked_at / expires_at columns; not
// persisted as an enum.
type InviteStatus string

const (
	InviteStatusPending  InviteStatus = "pending"
	InviteStatusAccepted InviteStatus = "accepted"
	InviteStatusRevoked  InviteStatus = "revoked"
	InviteStatusExpired  InviteStatus = "expired"
)

// Invite is a pending / accepted / revoked / expired invitation to add
// a seat to an account. RawToken is populated only on the return path
// from InviteToAccount so the caller (email adapter) can embed it in
// the signup link; the persisted row stores only TokenHash.
type Invite struct {
	ID              string
	AccountID       string
	InvitedBySeatID string
	InvitedEmail    string
	TokenHash       string
	// RawToken is set only on the just-created return path. Never
	// populated by a repository read — a persisted invite cannot
	// recover its raw token.
	RawToken   string
	ExpiresAt  time.Time
	AcceptedAt *time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
}

// Status returns the derived lifecycle state.
func (i Invite) Status(now time.Time) InviteStatus {
	switch {
	case i.AcceptedAt != nil:
		return InviteStatusAccepted
	case i.RevokedAt != nil:
		return InviteStatusRevoked
	case i.ExpiresAt.Before(now) || i.ExpiresAt.Equal(now):
		return InviteStatusExpired
	default:
		return InviteStatusPending
	}
}

// IsOpen reports whether the invite is still awaiting a response
// (pending — not accepted, not revoked, not expired).
func (i Invite) IsOpen(now time.Time) bool {
	return i.Status(now) == InviteStatusPending
}
