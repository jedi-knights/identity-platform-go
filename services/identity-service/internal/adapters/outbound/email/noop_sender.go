package email

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// Compile-time interface check.
var _ domain.EmailSender = (*NoopSender)(nil)

// NoopSender drops all messages. Useful when the service is intentionally
// configured without email delivery (e.g. an internal-only deployment that
// communicates verification tokens out-of-band).
type NoopSender struct{}

// NewNoopSender constructs a NoopSender.
func NewNoopSender() *NoopSender {
	return &NoopSender{}
}

// SendVerificationEmail returns nil without doing anything.
func (NoopSender) SendVerificationEmail(_ context.Context, _ domain.VerificationEmail) error {
	return nil
}

// SendPasswordResetEmail returns nil without doing anything.
func (NoopSender) SendPasswordResetEmail(_ context.Context, _ domain.PasswordResetEmail) error {
	return nil
}
