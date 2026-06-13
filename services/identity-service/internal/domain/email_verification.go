package domain

import (
	"context"
	"time"
)

// VerificationToken represents an outstanding email-verification token.
// Tokens are single-use: a non-nil UsedAt means the token has already been
// redeemed and must not be honoured again.
//
// The TokenHash field stores a SHA-256 hash of the plaintext token. The
// service hands the plaintext value back to the email sender and never to
// persistence, so a database leak does not expose live tokens.
type VerificationToken struct {
	TokenHash string
	UserID    string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// VerificationTokenRepository defines persistence operations for verification
// tokens.
type VerificationTokenRepository interface {
	// Save records a new verification token. Returning ErrCodeConflict is
	// acceptable if the hash collides (effectively impossible with SHA-256).
	Save(ctx context.Context, token *VerificationToken) error

	// FindByHash looks up a token by its stored SHA-256 hash. Returns a
	// not-found error when no row matches.
	FindByHash(ctx context.Context, tokenHash string) (*VerificationToken, error)

	// MarkUsed atomically sets UsedAt for the token. Implementations should
	// return a not-found error when the row no longer exists.
	MarkUsed(ctx context.Context, tokenHash string, usedAt time.Time) error

	// DeleteExpired prunes expired and used tokens older than `before`.
	// Returns the number of rows removed for operator visibility.
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
}

// EmailSender is the outbound port for transactional email. Implementations
// route the message to stdout, an in-process buffer, or an external provider
// (SES, Resend, SendGrid, …).
//
// Both URLs are fully-formed by the service before being handed off — the
// sender's job is transport, not composition.
type EmailSender interface {
	SendVerificationEmail(ctx context.Context, msg VerificationEmail) error
	SendPasswordResetEmail(ctx context.Context, msg PasswordResetEmail) error
}

// VerificationEmail is the payload handed to an EmailSender. All fields are
// pre-rendered — the sender just transports the message.
type VerificationEmail struct {
	To              string
	Name            string
	VerificationURL string
}

// RequestVerificationRequest is the inbound shape for asking the service to
// send a verification email to the user matching Email.
type RequestVerificationRequest struct {
	Email string `json:"email"`
}

// VerifyEmailRequest is the inbound shape for redeeming a verification token.
type VerifyEmailRequest struct {
	Token string `json:"token"`
}

// VerifyEmailResponse is returned on a successful verification.
type VerifyEmailResponse struct {
	UserID     string    `json:"user_id"`
	Email      string    `json:"email"`
	VerifiedAt time.Time `json:"verified_at"`
}
