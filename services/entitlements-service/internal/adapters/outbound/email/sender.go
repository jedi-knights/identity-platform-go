// Package email holds entitlements-service's outbound email
// adapters. Two implementations ship in-repo:
//
//   - stdout: prints the outbound email to stderr; the default for
//     local dev, CI, and reference-implementation deployments where
//     no SMTP is configured
//   - noop:   silently drops the send; useful in tests where the
//     email content is not asserted on
//
// Production SMTP / SES / SendGrid adapters plug in behind
// ports.EmailSender without touching the application layer.
package email

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/ports"
)

// Compile-time assertions.
var (
	_ ports.EmailSender = (*StdoutSender)(nil)
	_ ports.EmailSender = (*NoopSender)(nil)
)

// StdoutSender writes each outbound email as a single JSON line to w.
// Line-per-send lets an operator grep the CI log for the invite token
// during local flows.
type StdoutSender struct {
	w io.Writer
}

// NewStdoutSender returns a StdoutSender writing to stderr.
func NewStdoutSender() *StdoutSender {
	return &StdoutSender{w: os.Stderr}
}

// NewStdoutSenderTo returns a StdoutSender writing to w. Test-only.
func NewStdoutSenderTo(w io.Writer) *StdoutSender {
	return &StdoutSender{w: w}
}

// SendInvite marshals the invite email as a JSON line and writes it.
// Errors from the underlying writer surface unchanged so tests can
// assert on write failures without a wrapper mask.
func (s *StdoutSender) SendInvite(_ context.Context, msg ports.InviteEmail) error {
	rendered := map[string]string{
		"channel":      "email",
		"template":     "account_invite",
		"to":           msg.ToEmail,
		"account_name": msg.AccountName,
		"inviter_name": msg.InviterName,
		"signup_url":   msg.SignupURL,
		"expires_at":   msg.ExpiresAt,
	}
	data, err := json.Marshal(rendered)
	if err != nil {
		return fmt.Errorf("marshalling invite email: %w", err)
	}
	data = append(data, '\n')
	if _, err := s.w.Write(data); err != nil {
		return fmt.Errorf("writing invite email: %w", err)
	}
	return nil
}

// NoopSender drops every send. Useful in tests that do not assert on
// email content — the caller can verify the send happened via a
// separate mechanism (e.g. audit event).
type NoopSender struct{}

// NewNoopSender returns a NoopSender.
func NewNoopSender() *NoopSender { return &NoopSender{} }

// SendInvite always returns nil.
func (NoopSender) SendInvite(_ context.Context, _ ports.InviteEmail) error { return nil }
