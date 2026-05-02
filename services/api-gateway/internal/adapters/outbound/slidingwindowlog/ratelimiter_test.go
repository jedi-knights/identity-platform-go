//go:build unit

package slidingwindowlog_test

import (
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/slidingwindowlog"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.RateLimiter = (*slidingwindowlog.RateLimiter)(nil)

func TestSlidingWindowLog_AllowsUpToLimit(t *testing.T) {
	rl := slidingwindowlog.New(domain.SlidingWindowLogRule{
		RequestsPerWindow: 3,
		WindowDuration:    time.Second,
	})
	for i := range 3 {
		if !rl.Allow("client") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestSlidingWindowLog_DeniesOverLimit(t *testing.T) {
	rl := slidingwindowlog.New(domain.SlidingWindowLogRule{
		RequestsPerWindow: 2,
		WindowDuration:    time.Second,
	})
	rl.Allow("client")
	rl.Allow("client")
	if rl.Allow("client") {
		t.Fatal("third request should be denied")
	}
}

func TestSlidingWindowLog_AllowsAfterWindowSlides(t *testing.T) {
	rl := slidingwindowlog.New(domain.SlidingWindowLogRule{
		RequestsPerWindow: 1,
		WindowDuration:    60 * time.Millisecond,
	})
	if !rl.Allow("client") {
		t.Fatal("first request should be allowed")
	}
	if rl.Allow("client") {
		t.Fatal("second request should be denied while first is still in window")
	}
	time.Sleep(70 * time.Millisecond)
	// The first request has now slid out of the window.
	if !rl.Allow("client") {
		t.Fatal("request should be allowed once the window has slid past the first entry")
	}
}

func TestSlidingWindowLog_IndependentKeys(t *testing.T) {
	rl := slidingwindowlog.New(domain.SlidingWindowLogRule{
		RequestsPerWindow: 1,
		WindowDuration:    time.Second,
	})
	if !rl.Allow("a") {
		t.Fatal("a should be allowed")
	}
	if !rl.Allow("b") {
		t.Fatal("b should be allowed — independent log")
	}
}
