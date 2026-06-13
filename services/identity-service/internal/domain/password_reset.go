package domain

import (
	"context"
	"time"
)

// PasswordResetToken represents an outstanding password-reset token. Tokens
// are single-use; a non-nil UsedAt means the token has already been redeemed.
//
// Stored as a SHA-256 hex digest, the same pattern as verification tokens.
// The two flows are persisted in separate tables so revocation, rate
// limiting, and TTL can be tuned per-flow without coupling.
type PasswordResetToken struct {
	TokenHash string
	UserID    string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// PasswordResetTokenRepository defines persistence for password-reset tokens.
type PasswordResetTokenRepository interface {
	Save(ctx context.Context, token *PasswordResetToken) error
	FindByHash(ctx context.Context, tokenHash string) (*PasswordResetToken, error)
	MarkUsed(ctx context.Context, tokenHash string, usedAt time.Time) error
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
}

// PasswordResetEmail is the payload handed to an EmailSender for the
// password-reset flow. Distinct from VerificationEmail so the sender can
// render different copy / subject lines per email type.
type PasswordResetEmail struct {
	To       string
	Name     string
	ResetURL string
}

// RequestPasswordResetRequest is the inbound shape for asking the service to
// send a password-reset email to the user matching Email.
type RequestPasswordResetRequest struct {
	Email string `json:"email"`
}

// ResetPasswordRequest is the inbound shape for redeeming a reset token.
type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// ResetPasswordResponse is returned on a successful password reset. The
// response includes the user_id + email so the caller can immediately log
// the user in (or prompt them to).
type ResetPasswordResponse struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}
