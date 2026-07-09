// Package redis: PushedAuthorizationRequestRepository.
//
// Key schema: par:<request_uri> with TTL = ExpiresAt - now. Consume must
// be atomic read-and-delete for the same reason as AuthorizationCodeRepository
// — a request_uri must never be usable twice.

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
var _ domain.PushedAuthorizationRequestRepository = (*PushedAuthorizationRequestRepository)(nil)

const parKeyPrefix = "par:"

func parKey(requestURI string) string { return parKeyPrefix + requestURI }

// PushedAuthorizationRequestRepository is a Redis-backed pushed-
// authorization-request store. Requests live under "par:<request_uri>"
// with a TTL aligned to ExpiresAt; Redis handles expiry automatically.
type PushedAuthorizationRequestRepository struct {
	client *goredis.Client
}

// NewPushedAuthorizationRequestRepository creates a Redis-backed store.
func NewPushedAuthorizationRequestRepository(client *goredis.Client) *PushedAuthorizationRequestRepository {
	return &PushedAuthorizationRequestRepository{client: client}
}

// Save stores the request with TTL = ExpiresAt - now. Already-expired
// requests are silently dropped, mirroring AuthorizationCodeRepository.Save.
func (r *PushedAuthorizationRequestRepository) Save(ctx context.Context, req *domain.PushedAuthorizationRequest) error {
	ttl := time.Until(req.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshalling pushed authorization request: %w", err)
	}
	if err := r.client.Set(ctx, parKey(req.RequestURI), data, ttl).Err(); err != nil {
		return fmt.Errorf("saving pushed authorization request: %w", err)
	}
	return nil
}

// Consume atomically reads and deletes the request identified by
// requestURI, via the same GET+DEL Lua script AuthorizationCodeRepository
// uses. Returns ErrPushedAuthorizationRequestNotFound when the key does
// not exist (including already-consumed and expired cases).
func (r *PushedAuthorizationRequestRepository) Consume(ctx context.Context, requestURI string) (*domain.PushedAuthorizationRequest, error) {
	result, err := consumeScript.Run(ctx, r.client, []string{parKey(requestURI)}).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, domain.ErrPushedAuthorizationRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consuming pushed authorization request: %w", err)
	}
	if result == nil {
		return nil, domain.ErrPushedAuthorizationRequestNotFound
	}
	raw, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("pushed authorization request: unexpected Lua result type %T", result)
	}
	var req domain.PushedAuthorizationRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		return nil, fmt.Errorf("unmarshalling pushed authorization request: %w", err)
	}
	return &req, nil
}
