package memory

import (
	"context"
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// Compile-time interface check — fails at build time if DPoPProofRepository
// drifts from the domain interface. Marks the swap point for the Redis
// adapter (ADR-0005 / ADR-0025).
var _ domain.DPoPProofRepository = (*DPoPProofRepository)(nil)

// DPoPProofRepository is an in-memory replay cache for DPoP proof jti values
// (ADR-0025). Unlike AuthorizationCodeRepository (read-and-delete), this is
// "insert-if-absent, TTL'd" — a jti already recorded and not yet expired
// fails MarkUsed; an expired one is silently overwritten, since by then the
// proof itself would already fail the DPoPValidator's iat freshness check.
// Not safe for multi-replica deployments — each replica holds an independent
// cache. Production deployments use the Redis adapter.
type DPoPProofRepository struct {
	mu   sync.Mutex
	seen map[string]time.Time // jti -> expiresAt
}

// NewDPoPProofRepository creates an empty replay cache.
func NewDPoPProofRepository() *DPoPProofRepository {
	return &DPoPProofRepository{seen: make(map[string]time.Time)}
}

// MarkUsed records jti as used until expiresAt. Returns
// domain.ErrDPoPProofReplayed if jti is already recorded and has not
// expired.
//
// Sweeps expired entries on every call before checking — without this the
// map would grow without bound as distinct jtis arrive (every real proof
// has a fresh one). The sweep keeps steady-state size proportional to
// proof throughput over the freshness window, not total lifetime request
// count.
func (r *DPoPProofRepository) MarkUsed(_ context.Context, jti string, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for k, exp := range r.seen {
		if now.After(exp) {
			delete(r.seen, k)
		}
	}
	if exp, ok := r.seen[jti]; ok && now.Before(exp) {
		return domain.ErrDPoPProofReplayed
	}
	r.seen[jti] = expiresAt
	return nil
}
