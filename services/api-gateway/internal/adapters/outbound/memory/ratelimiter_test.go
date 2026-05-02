//go:build unit

package memory_test

import (
	"context"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

func newLimiter(rps float64, burst int) *memory.RateLimiter {
	return memory.NewRateLimiter(context.Background(), domain.RateLimitRule{
		RequestsPerSecond: rps,
		BurstSize:         burst,
	})
}

// TestRateLimiter_ImplementsRateLimiter is a compile-time guard.
func TestRateLimiter_ImplementsRateLimiter(t *testing.T) {
	var _ ports.RateLimiter = newLimiter(10, 10)
}

// TestRateLimiter_Allow_PermitsBurstRequests verifies that up to BurstSize
// requests are allowed immediately for a new key.
func TestRateLimiter_Allow_PermitsBurstRequests(t *testing.T) {
	burst := 5
	rl := newLimiter(100, burst)

	for i := range burst {
		if !rl.Allow("client-ip") {
			t.Errorf("request %d of burst %d was denied; all burst requests should be allowed", i+1, burst)
		}
	}
}

// TestRateLimiter_Allow_DeniesRequestsAboveBurst confirms that once the burst
// is exhausted the very next request is denied (token bucket is empty).
func TestRateLimiter_Allow_DeniesRequestsAboveBurst(t *testing.T) {
	burst := 3
	rl := newLimiter(0.001, burst) // near-zero refill rate so tokens don't replenish

	for range burst {
		rl.Allow("cli")
	}
	if rl.Allow("cli") {
		t.Error("request beyond burst capacity was allowed; should have been denied")
	}
}

// TestRateLimiter_Allow_DifferentKeysAreIndependent verifies that rate limits
// are per-key: exhausting one key does not affect another.
func TestRateLimiter_Allow_DifferentKeysAreIndependent(t *testing.T) {
	rl := newLimiter(0.001, 1) // burst=1, effectively one-shot per key

	if !rl.Allow("key-a") {
		t.Fatal("first request for key-a should be allowed")
	}
	// key-a is now exhausted; key-b should still be allowed (fresh bucket).
	if !rl.Allow("key-b") {
		t.Error("first request for key-b should be allowed independently of key-a")
	}
}
