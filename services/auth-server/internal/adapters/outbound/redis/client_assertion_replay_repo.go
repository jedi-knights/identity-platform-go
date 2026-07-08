// Package redis: ClientAssertionReplayRepository for RFC 7523 client
// assertion jti replay protection (ADR-0023).
//
// Key schema: clientassertion-jti:<jti> with TTL = expiresAt - now. Unlike
// every other repository in this package, MarkUsed is "insert if absent"
// rather than "read and delete" — Redis's SET...NX EX already provides
// exactly that atomicity server-side, so no Lua script is needed here.

package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// Compile-time interface check — fails to build if the adapter drifts.
var _ domain.ClientAssertionReplayRepository = (*ClientAssertionReplayRepository)(nil)

const clientAssertionJTIKeyPrefix = "clientassertion-jti:"

func clientAssertionJTIKey(jti string) string { return clientAssertionJTIKeyPrefix + jti }

// ClientAssertionReplayRepository is the Redis-backed store for RFC 7523
// client-assertion replay protection.
type ClientAssertionReplayRepository struct {
	client *goredis.Client
}

// NewClientAssertionReplayRepository wires the adapter to a connected Redis client.
func NewClientAssertionReplayRepository(client *goredis.Client) *ClientAssertionReplayRepository {
	return &ClientAssertionReplayRepository{client: client}
}

// MarkUsed atomically records jti via SET NX EX. A TTL of zero or less
// (an already-expired assertion) is treated as a no-op success — there is
// nothing to remember once the assertion itself would already be
// rejected as expired.
func (r *ClientAssertionReplayRepository) MarkUsed(ctx context.Context, jti string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil
	}
	err := r.client.SetArgs(ctx, clientAssertionJTIKey(jti), "1", goredis.SetArgs{Mode: "NX", TTL: ttl}).Err()
	if errors.Is(err, goredis.Nil) {
		return domain.ErrClientAssertionReplayed
	}
	if err != nil {
		return fmt.Errorf("recording client assertion jti: %w", err)
	}
	return nil
}
