// Package redis provides a Redis-backed token repository for the auth-server.
// Key schema: token:<raw-jwt> with TTL equal to the token's remaining lifetime.
// Auth-server is the sole writer; token-introspection-service reads using the same schema.
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// Compile-time interface check — fails at build time if TokenRepository drifts
// from the domain.TokenRepository interface. This marks the swap point for scaling
// beyond a single replica (see ADR-0005).
var _ domain.TokenRepository = (*TokenRepository)(nil)

const keyPrefix = "token:"

// TokenRepository is a Redis-backed token repository.
// Tokens are stored under "token:<raw-jwt>" with a TTL set to the token's
// remaining lifetime so Redis handles expiry automatically.
// Safe for concurrent use — go-redis manages its own connection pool.
type TokenRepository struct {
	client *goredis.Client
}

// NewTokenRepository creates a TokenRepository backed by the given Redis client.
func NewTokenRepository(client *goredis.Client) *TokenRepository {
	return &TokenRepository{client: client}
}

func tokenKey(raw string) string { return keyPrefix + raw }

// Save stores the token in Redis with a TTL equal to the token's remaining
// lifetime. Tokens that are already expired are silently dropped — there is
// no point persisting a token that can never be active.
func (r *TokenRepository) Save(ctx context.Context, token *domain.Token) error {
	ttl := time.Until(token.ExpiresAt)
	if ttl <= 0 {
		// Already expired — skip storage; FindByRaw will return ErrTokenNotFound.
		return nil
	}
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("marshalling token: %w", err)
	}
	if err := r.client.Set(ctx, tokenKey(token.Raw), data, ttl).Err(); err != nil {
		return fmt.Errorf("saving token: %w", err)
	}
	return nil
}

// FindByRaw retrieves a token by its raw JWT string.
// Returns domain.ErrTokenNotFound (wrapped) when the key does not exist or has expired.
func (r *TokenRepository) FindByRaw(ctx context.Context, raw string) (*domain.Token, error) {
	data, err := r.client.Get(ctx, tokenKey(raw)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, fmt.Errorf("%w", domain.ErrTokenNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("fetching token: %w", err)
	}
	var token domain.Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("unmarshalling token: %w", err)
	}
	return &token, nil
}

// Delete removes the token from Redis.
// Per RFC 7009 §2.2, revoking an already-revoked or never-issued token is not
// an error from the caller's perspective. This method returns an
// apperrors.ErrCodeNotFound-wrapped error so the revocation handler can treat it
// as a successful idempotent revocation rather than an infrastructure failure.
func (r *TokenRepository) Delete(ctx context.Context, raw string) error {
	n, err := r.client.Del(ctx, tokenKey(raw)).Result()
	if err != nil {
		return fmt.Errorf("deleting token: %w", err)
	}
	if n == 0 {
		// Token was already expired (TTL elapsed) or never stored — RFC 7009 idempotent.
		return apperrors.New(apperrors.ErrCodeNotFound, "token not found")
	}
	return nil
}

// NewClient creates a go-redis Client from a Redis URL.
// Supported URL formats:
//
//	redis://host:port
//	redis://:password@host:port/db
//	rediss://host:port  (TLS)
func NewClient(redisURL string) (*goredis.Client, error) {
	opts, err := goredis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parsing redis URL: %w", err)
	}
	return goredis.NewClient(opts), nil
}
