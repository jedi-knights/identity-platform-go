// Package email provides outbound email-sender adapters.
//
// Three implementations ship today:
//
//   - StdoutSender — logs the message as a structured slog record. Suitable
//     as the development default; the verification URL is printed to the
//     service's stdout where operators can copy it during local testing.
//   - NoopSender   — drops the message silently. Useful when the service is
//     intentionally configured without email delivery.
//   - BufferSender — keeps messages in memory for inspection in tests.
//
// External SMTP / SES / Resend / SendGrid adapters can implement
// domain.EmailSender alongside these without touching the application layer.
package email

import (
	"context"

	"github.com/jedi-knights/go-logging/pkg/logging"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// Compile-time interface check.
var _ domain.EmailSender = (*StdoutSender)(nil)

// StdoutSender writes outgoing emails to the structured logger. The
// verification URL is included verbatim so operators can copy and use it
// during local development.
type StdoutSender struct {
	logger logging.Logger
}

// NewStdoutSender constructs a logger-backed sender.
func NewStdoutSender(logger logging.Logger) *StdoutSender {
	return &StdoutSender{logger: logger}
}

// SendVerificationEmail logs the message.
func (s *StdoutSender) SendVerificationEmail(_ context.Context, msg domain.VerificationEmail) error {
	s.logger.Info(
		"email.send",
		"kind", "verification",
		"to", msg.To,
		"name", msg.Name,
		"verification_url", msg.VerificationURL,
	)
	return nil
}
