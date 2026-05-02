//go:build unit

package fixedwindow_test

import (
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/fixedwindow"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.RateLimiter = (*fixedwindow.RateLimiter)(nil)

func TestFixedWindow_AllowsUpToLimit(t *testing.T) {
	rl := fixedwindow.New(domain.FixedWindowRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: 3,
		WindowDuration:    time.Second,
	}})
	for i := range 3 {
		if !rl.Allow("client") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestFixedWindow_DeniesOverLimit(t *testing.T) {
	rl := fixedwindow.New(domain.FixedWindowRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: 2,
		WindowDuration:    time.Second,
	}})
	rl.Allow("client")
	rl.Allow("client")
	if rl.Allow("client") {
		t.Fatal("third request should be denied")
	}
}

func TestFixedWindow_ResetsAfterWindow(t *testing.T) {
	rl := fixedwindow.New(domain.FixedWindowRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: 1,
		WindowDuration:    50 * time.Millisecond,
	}})
	if !rl.Allow("client") {
		t.Fatal("first request should be allowed")
	}
	if rl.Allow("client") {
		t.Fatal("second request in same window should be denied")
	}
	time.Sleep(60 * time.Millisecond)
	if !rl.Allow("client") {
		t.Fatal("first request of new window should be allowed")
	}
}

func TestFixedWindow_IndependentKeys(t *testing.T) {
	rl := fixedwindow.New(domain.FixedWindowRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: 1,
		WindowDuration:    time.Second,
	}})
	if !rl.Allow("a") {
		t.Fatal("a should be allowed")
	}
	if !rl.Allow("b") {
		t.Fatal("b should be allowed — independent bucket")
	}
	if rl.Allow("a") {
		t.Fatal("a's second request should be denied")
	}
}
