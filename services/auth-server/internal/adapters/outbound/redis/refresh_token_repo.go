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

// Compile-time interface check — fails at build time if RefreshTokenRepository drifts
// from the domain.RefreshTokenRepository interface. This marks the swap point for scaling
// beyond a single replica (see ADR-0005).
var _ domain.RefreshTokenRepository = (*RefreshTokenRepository)(nil)

// RefreshTokenRepository stores refresh tokens in Redis.
// Key format: refresh_token:<raw>
// TTL is set to the token's remaining lifetime at Save time.
// Safe for concurrent use — go-redis manages its own connection pool.
type RefreshTokenRepository struct {
	client *goredis.Client
}

// NewRefreshTokenRepository creates a RefreshTokenRepository backed by the given Redis client.
func NewRefreshTokenRepository(client *goredis.Client) *RefreshTokenRepository {
	return &RefreshTokenRepository{client: client}
}

func refreshTokenKey(raw string) string { return "refresh_token:" + raw }

// Save stores the refresh token with a TTL equal to its remaining lifetime.
// Returns an error if the token is already expired — there is no value in
// persisting a token that can never be used.
func (r *RefreshTokenRepository) Save(ctx context.Context, token *domain.RefreshToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("marshalling refresh token: %w", err)
	}
	ttl := time.Until(token.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("refresh token already expired")
	}
	if err := r.client.Set(ctx, refreshTokenKey(token.Raw), data, ttl).Err(); err != nil {
		return fmt.Errorf("saving refresh token: %w", err)
	}
	return nil
}

// FindByRaw retrieves a refresh token by its raw value.
// Returns domain.ErrRefreshTokenNotFound when the key does not exist or has expired.
func (r *RefreshTokenRepository) FindByRaw(ctx context.Context, raw string) (*domain.RefreshToken, error) {
	data, err := r.client.Get(ctx, refreshTokenKey(raw)).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return nil, domain.ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("finding refresh token: %w", err)
	}
	var token domain.RefreshToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("unmarshalling refresh token: %w", err)
	}
	return &token, nil
}

// Delete removes a refresh token. Returns domain.ErrRefreshTokenNotFound when not present.
// Per RFC 7009 §2.2, deletion of a non-existent token is surfaced as ErrRefreshTokenNotFound
// so callers can decide whether to treat it as an error or an idempotent success.
func (r *RefreshTokenRepository) Delete(ctx context.Context, raw string) error {
	n, err := r.client.Del(ctx, refreshTokenKey(raw)).Result()
	if err != nil {
		return fmt.Errorf("deleting refresh token: %w", err)
	}
	if n == 0 {
		return domain.ErrRefreshTokenNotFound
	}
	return nil
}
