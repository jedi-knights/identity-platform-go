package domain

import "time"

// RateLimitRule defines the rate limit parameters.
type RateLimitRule struct {
	RequestsPerSecond float64
	BurstSize         int
}

// TokenBucket tracks the token bucket state for a single client.
// The algorithm is pure — the caller provides the current time
// so that this remains testable without mocking the clock.
type TokenBucket struct {
	tokens     float64
	lastRefill time.Time
	rule       RateLimitRule
}

// NewTokenBucket creates a bucket pre-filled to burst capacity.
func NewTokenBucket(rule RateLimitRule, now time.Time) *TokenBucket {
	return &TokenBucket{
		tokens:     float64(rule.BurstSize),
		lastRefill: now,
		rule:       rule,
	}
}

// Allow checks whether a request is permitted and consumes one token.
// It refills tokens based on elapsed time since the last refill.
func (b *TokenBucket) Allow(now time.Time) bool {
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * b.rule.RequestsPerSecond
	if b.tokens > float64(b.rule.BurstSize) {
		b.tokens = float64(b.rule.BurstSize)
	}
	b.lastRefill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
