package email

import (
	"context"
	"sync"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// Compile-time interface check.
var _ domain.EmailSender = (*BufferSender)(nil)

// BufferSender keeps every message in memory for inspection. It is intended
// for tests; production stacks must use a real sender.
type BufferSender struct {
	mu              sync.Mutex
	verifications   []domain.VerificationEmail
	passwordResets  []domain.PasswordResetEmail
}

// NewBufferSender constructs an empty buffer.
func NewBufferSender() *BufferSender {
	return &BufferSender{}
}

// SendVerificationEmail appends to the verification buffer.
func (b *BufferSender) SendVerificationEmail(_ context.Context, msg domain.VerificationEmail) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.verifications = append(b.verifications, msg)
	return nil
}

// SendPasswordResetEmail appends to the password-reset buffer.
func (b *BufferSender) SendPasswordResetEmail(_ context.Context, msg domain.PasswordResetEmail) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.passwordResets = append(b.passwordResets, msg)
	return nil
}

// Drain returns every verification message sent so far and resets that buffer.
func (b *BufferSender) Drain() []domain.VerificationEmail {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]domain.VerificationEmail, len(b.verifications))
	copy(out, b.verifications)
	b.verifications = b.verifications[:0]
	return out
}

// DrainPasswordResets returns every password-reset message sent so far and
// resets that buffer.
func (b *BufferSender) DrainPasswordResets() []domain.PasswordResetEmail {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]domain.PasswordResetEmail, len(b.passwordResets))
	copy(out, b.passwordResets)
	b.passwordResets = b.passwordResets[:0]
	return out
}
