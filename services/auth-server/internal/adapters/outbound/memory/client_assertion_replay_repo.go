package memory

import (
	"context"
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// Compile-time interface check — fails at build time if
// ClientAssertionReplayRepository drifts from the domain interface.
var _ domain.ClientAssertionReplayRepository = (*ClientAssertionReplayRepository)(nil)

// ClientAssertionReplayRepository is an in-memory store for RFC 7523
// client-assertion jti replay protection (ADR-0023). Not safe for
// multi-replica deployments — each replica holds an independent copy.
// Production deployments use the Redis adapter; this exists for local
// development without the full stack.
type ClientAssertionReplayRepository struct {
	mu   sync.Mutex
	seen map[string]time.Time // jti -> expiresAt
}

// NewClientAssertionReplayRepository creates an empty store.
func NewClientAssertionReplayRepository() *ClientAssertionReplayRepository {
	return &ClientAssertionReplayRepository{seen: make(map[string]time.Time)}
}

// MarkUsed atomically checks-and-records jti. The single mutex held
// across the lookup and the insert is what makes the operation atomic —
// concurrent callers serialize on the lock, exactly one records the jti,
// the rest see ErrClientAssertionReplayed.
//
// An entry whose recorded expiresAt has already passed is treated as
// absent (and overwritten) rather than replayed — see the domain
// interface's doc comment for why remembering it further serves no
// purpose.
func (r *ClientAssertionReplayRepository) MarkUsed(_ context.Context, jti string, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if exp, ok := r.seen[jti]; ok && time.Now().Before(exp) {
		return domain.ErrClientAssertionReplayed
	}
	r.seen[jti] = expiresAt
	return nil
}
