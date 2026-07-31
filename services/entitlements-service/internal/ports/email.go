package ports

import "context"

// InviteEmail carries the fully-rendered fields the outbound EmailSender
// needs to compose an invite email. RawToken is the un-hashed one-time
// value the recipient will POST back to the accept endpoint (follow-up
// story) — it lives in the email link only, never in the database.
type InviteEmail struct {
	ToEmail     string
	AccountName string
	InviterName string
	SignupURL   string // fully-rendered URL containing RawToken
	ExpiresAt   string // pre-formatted for the email template
}

// EmailSender is entitlements-service's outbound email port. Adapters:
//
//   - stdout — prints the email to stderr; the default for local dev
//     and CI so nothing surprising happens without an SMTP configured
//   - noop   — silently drops the send; useful in tests
//
// Real SMTP / SES / SendGrid adapters plug in behind this interface
// without touching the application layer.
type EmailSender interface {
	SendInvite(ctx context.Context, msg InviteEmail) error
}
