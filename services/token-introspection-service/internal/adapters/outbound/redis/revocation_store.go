package redis

import (
	"context"
	"fmt"

	goredis "github.com/redis/go-redis/v9"

	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
)

// Compile-time interface check — catches drift if domain.RevocationChecker changes.
var _ domain.RevocationChecker = (*RevocationStore)(nil)

// keyPrefix is the namespace auth-server uses when storing active tokens in Redis.
// A key exists while the token is valid and is deleted on revocation.
// Key format: "token:<raw-jwt>" — auth-server writes this on token issuance and
// deletes it on revocation (RFC 7009). This adapter is read-only; it must never write
// or delete keys, as that would corrupt auth-server's revocation state.
const keyPrefix = "token:"

// RevocationStore checks the auth-server Redis keyspace for token presence.
// A token is considered active if its key exists; revoked or expired tokens have no key.
// This adapter is read-only — auth-server is the sole writer.
type RevocationStore struct {
	client *goredis.Client
}

// NewRevocationStore returns a RevocationStore backed by the given Redis client.
func NewRevocationStore(client *goredis.Client) *RevocationStore {
	return &RevocationStore{client: client}
}

// IsActive returns true if the key token:<raw> exists in Redis.
// A missing key means the token was revoked by auth-server or never issued.
//
// TODO(security): the key suffix is the raw JWT string. Consider switching to
// SHA-256(raw) in both auth-server and here so tokens are not exposed in Redis
// keyspace, slow logs, or MONITOR output. Requires a coordinated change and an ADR.
func (s *RevocationStore) IsActive(ctx context.Context, raw string) (bool, error) {
	n, err := s.client.Exists(ctx, keyPrefix+raw).Result()
	if err != nil {
		return false, fmt.Errorf("checking token revocation: %w", err)
	}
	return n > 0, nil
}

// NewClient creates a Redis client from a Redis URL (e.g. redis://localhost:6379/0).
func NewClient(redisURL string) (*goredis.Client, error) {
	opts, err := goredis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parsing redis URL: %w", err)
	}
	return goredis.NewClient(opts), nil
}
