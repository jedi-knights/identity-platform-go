// Package redis: DPoPProofRepository.
//
// Key schema: dpop-jti:<jti> with TTL = expiresAt - now. Unlike
// AuthorizationCodeRepository's read-and-delete Consume, this needs
// "insert-if-absent" — SET NX EX gives that atomically in a single round
// trip; no Lua script needed.

package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// Compile-time interface check — fails at build time if the adapter drifts
// from the domain interface.
var _ domain.DPoPProofRepository = (*DPoPProofRepository)(nil)

const dpopJTIKeyPrefix = "dpop-jti:"

func dpopJTIKey(jti string) string { return dpopJTIKeyPrefix + jti }

// DPoPProofRepository is a Redis-backed DPoP proof replay cache (ADR-0025).
// jti values live under "dpop-jti:<jti>" with a TTL aligned to expiresAt;
// Redis expires them automatically — there is no janitor process.
type DPoPProofRepository struct {
	client *goredis.Client
}

// NewDPoPProofRepository creates a Redis-backed replay cache.
func NewDPoPProofRepository(client *goredis.Client) *DPoPProofRepository {
	return &DPoPProofRepository{client: client}
}

// MarkUsed records jti as used until expiresAt via SET NX EX (the current,
// non-deprecated form — SetNX itself is deprecated as of Redis 2.6.12) — the
// SET only succeeds if the key is absent, giving atomic insert-if-absent
// semantics in one round trip. Returns domain.ErrDPoPProofReplayed when the
// key already exists (a live, unexpired replay — Redis's own TTL already
// means a previously-used-and-expired jti simply isn't there to collide
// with).
func (r *DPoPProofRepository) MarkUsed(ctx context.Context, jti string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		ttl = time.Second // already expired; still record it briefly rather than skip the check
	}
	res, err := r.client.SetArgs(ctx, dpopJTIKey(jti), "1", goredis.SetArgs{Mode: "NX", TTL: ttl}).Result()
	if err != nil && !errors.Is(err, goredis.Nil) {
		return fmt.Errorf("marking dpop proof jti used: %w", err)
	}
	if errors.Is(err, goredis.Nil) || res == "" {
		return domain.ErrDPoPProofReplayed
	}
	return nil
}
