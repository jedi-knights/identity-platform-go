//go:build unit

package leakybucket_test

import (
	"context"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/leakybucket"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.RateLimiter = (*leakybucket.RateLimiter)(nil)

func TestLeakyBucket_AllowsUpToQueueDepth(t *testing.T) {
	rl := leakybucket.New(context.Background(), domain.LeakyBucketRule{
		DrainRatePerSecond: 1,
		QueueDepth:         3,
	})
	for i := range 3 {
		if !rl.Allow("client") {
			t.Fatalf("request %d should be allowed (queue not full)", i+1)
		}
	}
}

func TestLeakyBucket_DeniesWhenQueueFull(t *testing.T) {
	rl := leakybucket.New(context.Background(), domain.LeakyBucketRule{
		DrainRatePerSecond: 1,
		QueueDepth:         2,
	})
	rl.Allow("client")
	rl.Allow("client")
	if rl.Allow("client") {
		t.Fatal("request should be denied when queue is full")
	}
}

func TestLeakyBucket_AllowsAfterDrain(t *testing.T) {
	rl := leakybucket.New(context.Background(), domain.LeakyBucketRule{
		DrainRatePerSecond: 20, // drain one token every 50ms
		QueueDepth:         1,
	})
	if !rl.Allow("client") {
		t.Fatal("first request should be allowed")
	}
	if rl.Allow("client") {
		t.Fatal("second request should be denied (queue full)")
	}
	time.Sleep(60 * time.Millisecond) // wait for one drain interval
	if !rl.Allow("client") {
		t.Fatal("request should be allowed after drain")
	}
}

func TestLeakyBucket_IndependentKeys(t *testing.T) {
	rl := leakybucket.New(context.Background(), domain.LeakyBucketRule{
		DrainRatePerSecond: 1,
		QueueDepth:         1,
	})
	if !rl.Allow("a") {
		t.Fatal("a should be allowed")
	}
	if !rl.Allow("b") {
		t.Fatal("b should be allowed — independent queue")
	}
}
