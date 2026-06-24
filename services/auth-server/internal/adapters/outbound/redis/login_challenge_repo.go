// Package redis: LoginChallengeRepository for /oauth/authorize state.
//
// Mirrors the authcode adapter — Save uses SETEX with TTL = ExpiresAt - now;
// Consume is a single Lua script GET+DEL so two concurrent
// /internal/issue-code calls cannot both succeed.

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

// Compile-time interface check — fails to build if the adapter drifts.
var _ domain.LoginChallengeRepository = (*LoginChallengeRepository)(nil)

const loginChallengeKeyPrefix = "login_challenge:"

func loginChallengeKey(id string) string { return loginChallengeKeyPrefix + id }

// consumeChallengeScript reads and deletes the key in a single Redis
// server-side step. Identical shape to consumeScript (authcode adapter);
// kept separate so each store evolves without disturbing the other.
var consumeChallengeScript = goredis.NewScript(`
local v = redis.call('GET', KEYS[1])
if not v then
  return nil
end
redis.call('DEL', KEYS[1])
return v
`)

// LoginChallengeRepository is the Redis-backed store for in-flight
// /oauth/authorize state. Records live under login_challenge:<id> with a
// TTL aligned to ExpiresAt; Redis handles expiry automatically.
type LoginChallengeRepository struct {
	client *goredis.Client
}

// NewLoginChallengeRepository wires the adapter to a connected Redis client.
func NewLoginChallengeRepository(client *goredis.Client) *LoginChallengeRepository {
	return &LoginChallengeRepository{client: client}
}

// Save stores the challenge with TTL = ExpiresAt - now. Already-expired
// challenges are silently dropped — defensive guard for callers that pass
// a stale record.
func (r *LoginChallengeRepository) Save(ctx context.Context, c *domain.LoginChallenge) error {
	ttl := time.Until(c.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshalling login challenge: %w", err)
	}
	if err := r.client.Set(ctx, loginChallengeKey(c.ID), data, ttl).Err(); err != nil {
		return fmt.Errorf("saving login challenge: %w", err)
	}
	return nil
}

// Get returns the stored challenge without removing it. Maps the
// missing-key case to ErrLoginChallengeNotFound so the caller never has to
// import go-redis to decide whether the record exists.
func (r *LoginChallengeRepository) Get(ctx context.Context, id string) (*domain.LoginChallenge, error) {
	raw, err := r.client.Get(ctx, loginChallengeKey(id)).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, domain.ErrLoginChallengeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("fetching login challenge: %w", err)
	}
	var c domain.LoginChallenge
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, fmt.Errorf("unmarshalling login challenge: %w", err)
	}
	return &c, nil
}

// Update overwrites the stored record. Used by the consent flow to add
// SessionID / ConsentGranted before /internal/issue-code redemption.
// Returns ErrLoginChallengeNotFound when the key is absent — XX is the
// SET option that asserts the key already exists.
func (r *LoginChallengeRepository) Update(ctx context.Context, c *domain.LoginChallenge) error {
	ttl := time.Until(c.ExpiresAt)
	if ttl <= 0 {
		return domain.ErrLoginChallengeNotFound
	}
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshalling login challenge: %w", err)
	}
	res := r.client.SetArgs(ctx, loginChallengeKey(c.ID), data, goredis.SetArgs{Mode: "XX", TTL: ttl})
	switch {
	case errors.Is(res.Err(), goredis.Nil):
		return domain.ErrLoginChallengeNotFound
	case res.Err() != nil:
		return fmt.Errorf("updating login challenge: %w", res.Err())
	}
	return nil
}

// Consume atomically reads and deletes the challenge in a single
// server-side Lua script. ErrLoginChallengeNotFound on miss; bytes
// unmarshal on hit.
func (r *LoginChallengeRepository) Consume(ctx context.Context, id string) (*domain.LoginChallenge, error) {
	result, err := consumeChallengeScript.Run(ctx, r.client, []string{loginChallengeKey(id)}).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, domain.ErrLoginChallengeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consuming login challenge: %w", err)
	}
	if result == nil {
		return nil, domain.ErrLoginChallengeNotFound
	}
	raw, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("login challenge: unexpected Lua result type %T", result)
	}
	var c domain.LoginChallenge
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, fmt.Errorf("unmarshalling login challenge: %w", err)
	}
	return &c, nil
}
