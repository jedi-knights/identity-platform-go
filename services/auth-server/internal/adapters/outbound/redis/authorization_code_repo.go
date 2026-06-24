// Package redis: AuthorizationCodeRepository.
//
// Key schema: authcode:<raw> with TTL = ExpiresAt - now. The Consume
// operation must be atomic read-and-delete — two concurrent token-endpoint
// requests for the same code MUST NOT both succeed. A naive GET followed by
// DEL admits the race; we use a Lua script so Redis executes the read and
// the delete in one server-side step under a single key lock.

package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// Compile-time interface check — fails at build time if the adapter drifts
// from the domain interface.
var _ domain.AuthorizationCodeRepository = (*AuthorizationCodeRepository)(nil)

const authCodeKeyPrefix = "authcode:"

func authCodeKey(raw string) string { return authCodeKeyPrefix + raw }

// consumeScript is a Lua script that reads the value at KEYS[1] and deletes
// it in one Redis server-side step. Returns the previous value or nil if the
// key did not exist. Both branches use the same return path so the script is
// load-once / EVALSHA-call thereafter.
var consumeScript = goredis.NewScript(`
local v = redis.call('GET', KEYS[1])
if not v then
  return nil
end
redis.call('DEL', KEYS[1])
return v
`)

// AuthorizationCodeRepository is a Redis-backed authorization-code store.
// Codes live under "authcode:<raw>" with a TTL aligned to ExpiresAt; Redis
// handles expiry automatically — there is no janitor process.
type AuthorizationCodeRepository struct {
	client *goredis.Client
}

// NewAuthorizationCodeRepository creates a Redis-backed code store.
func NewAuthorizationCodeRepository(client *goredis.Client) *AuthorizationCodeRepository {
	return &AuthorizationCodeRepository{client: client}
}

// Save stores the code with TTL = ExpiresAt - now. Already-expired codes are
// silently dropped — the platform should never call Save on one of those
// (the issuer freshly stamps ExpiresAt), but the guard avoids loading the
// store with stale entries if it ever does.
func (r *AuthorizationCodeRepository) Save(ctx context.Context, code *domain.AuthorizationCode) error {
	ttl := time.Until(code.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	data, err := json.Marshal(code)
	if err != nil {
		return fmt.Errorf("marshalling authorization code: %w", err)
	}
	if err := r.client.Set(ctx, authCodeKey(code.Code), data, ttl).Err(); err != nil {
		return fmt.Errorf("saving authorization code: %w", err)
	}
	return nil
}

// Consume atomically reads and deletes the code identified by raw. Returns
// ErrAuthorizationCodeNotFound when the key does not exist (including
// already-consumed and expired cases). The atomicity is provided by the
// server-side Lua script; the application path that follows this call can
// assume that no other consumer will see the same code.
func (r *AuthorizationCodeRepository) Consume(ctx context.Context, raw string) (*domain.AuthorizationCode, error) {
	result, err := consumeScript.Run(ctx, r.client, []string{authCodeKey(raw)}).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, domain.ErrAuthorizationCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consuming authorization code: %w", err)
	}
	// The script returns a Redis bulk string; go-redis decodes it as a string
	// at this Result() boundary. A nil interface here means the script's
	// `return nil` branch fired (key absent) — same as goredis.Nil above for
	// callers, but go-redis maps script-nil to a typed nil interface{}.
	if result == nil {
		return nil, domain.ErrAuthorizationCodeNotFound
	}
	raw, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("authorization code: unexpected Lua result type %T", result)
	}
	var code domain.AuthorizationCode
	if err := json.Unmarshal([]byte(raw), &code); err != nil {
		return nil, fmt.Errorf("unmarshalling authorization code: %w", err)
	}
	return &code, nil
}
