// Package redis provides Redis-backed adapter implementations for the
// authorization-policy-service.
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/ports"
)

// CachingPolicyEvaluator wraps a PolicyEvaluator and caches evaluation results in Redis.
// Cache key format: authz:{subject_id}:{resource}:{action}  (each component percent-encoded)
// Cache value: JSON-encoded domain.EvaluationResponse (preserves the Reason field)
// On Redis error the decorator falls through to the inner evaluator (fail-open for the cache layer).
type CachingPolicyEvaluator struct {
	inner  ports.PolicyEvaluator
	client *goredis.Client
	ttl    time.Duration
	logger logging.Logger
}

// NewClient parses redisURL and returns a connected Redis client.
func NewClient(redisURL string) (*goredis.Client, error) {
	opts, err := goredis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parsing redis URL: %w", err)
	}
	return goredis.NewClient(opts), nil
}

// NewCachingPolicyEvaluator returns a CachingPolicyEvaluator that wraps inner with a Redis cache.
func NewCachingPolicyEvaluator(inner ports.PolicyEvaluator, client *goredis.Client, ttl time.Duration, logger logging.Logger) *CachingPolicyEvaluator {
	return &CachingPolicyEvaluator{inner: inner, client: client, ttl: ttl, logger: logger}
}

// CacheKey builds a Redis key for the given subject, resource, and action.
// Each component is percent-encoded so that colon characters in field values
// cannot collide with the separator colons in the key structure.
// Format: authz:{encoded_subject}:{encoded_resource}:{encoded_action}.
func CacheKey(subjectID, resource, action string) string {
	return fmt.Sprintf("authz:%s:%s:%s",
		url.QueryEscape(subjectID),
		url.QueryEscape(resource),
		url.QueryEscape(action),
	)
}

// EncodeCacheValue serialises resp to a JSON string for storage in Redis.
// JSON preserves the Reason field, which would be lost if only the allowed
// boolean were stored as "1"/"0".
func EncodeCacheValue(resp *domain.EvaluationResponse) string {
	b, _ := json.Marshal(resp) // EvaluationResponse contains only string/bool — Marshal never errors
	return string(b)
}

// DecodeCacheValue deserialises a JSON string produced by EncodeCacheValue back
// into an EvaluationResponse.
func DecodeCacheValue(val string) (*domain.EvaluationResponse, error) {
	var resp domain.EvaluationResponse
	if err := json.Unmarshal([]byte(val), &resp); err != nil {
		return nil, fmt.Errorf("decoding cache value: %w", err)
	}
	return &resp, nil
}

// Evaluate checks the cache first; on miss calls inner and writes back.
// A Redis failure at any point causes the decorator to bypass the cache and
// call the inner evaluator directly, so availability is preserved.
func (c *CachingPolicyEvaluator) Evaluate(ctx context.Context, req domain.EvaluationRequest) (*domain.EvaluationResponse, error) {
	key := CacheKey(req.SubjectID, req.Resource, req.Action)

	val, err := c.client.Get(ctx, key).Result()
	if err == nil {
		resp, decErr := DecodeCacheValue(val)
		if decErr != nil {
			c.logger.Warn("policy cache decode failed, bypassing cache", "error", decErr)
		} else {
			return resp, nil
		}
	}
	if !errors.Is(err, goredis.Nil) && err != nil {
		c.logger.Warn("policy cache get failed, bypassing cache", "error", err)
	}

	resp, err := c.inner.Evaluate(ctx, req)
	if err != nil {
		return nil, err
	}

	if setErr := c.client.Set(ctx, key, EncodeCacheValue(resp), c.ttl).Err(); setErr != nil {
		c.logger.Warn("policy cache set failed", "error", setErr)
	}

	return resp, nil
}
