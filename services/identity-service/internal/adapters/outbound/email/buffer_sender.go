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
	mu   sync.Mutex
	msgs []domain.VerificationEmail
}

// NewBufferSender constructs an empty buffer.
func NewBufferSender() *BufferSender {
	return &BufferSender{}
}

// SendVerificationEmail appends to the buffer.
func (b *BufferSender) SendVerificationEmail(_ context.Context, msg domain.VerificationEmail) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.msgs = append(b.msgs, msg)
	return nil
}

// Drain returns every message sent so far and resets the buffer.
func (b *BufferSender) Drain() []domain.VerificationEmail {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]domain.VerificationEmail, len(b.msgs))
	copy(out, b.msgs)
	b.msgs = b.msgs[:0]
	return out
}
