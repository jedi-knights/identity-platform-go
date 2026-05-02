//go:build unit

package memory_test

import (
	"fmt"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.ConcurrencyLimiter = (*memory.ConcurrencyLimiter)(nil)

func TestConcurrencyLimiter_AcquiresUpToLimit(t *testing.T) {
	cl := memory.NewConcurrencyLimiter(domain.ConcurrencyRule{MaxInFlight: 2})
	if !cl.Acquire("client") {
		t.Fatal("first Acquire should succeed")
	}
	if !cl.Acquire("client") {
		t.Fatal("second Acquire should succeed")
	}
}

func TestConcurrencyLimiter_DeniesAtLimit(t *testing.T) {
	cl := memory.NewConcurrencyLimiter(domain.ConcurrencyRule{MaxInFlight: 1})
	if !cl.Acquire("client") {
		t.Fatal("first Acquire should succeed")
	}
	if cl.Acquire("client") {
		t.Fatal("second Acquire should be denied")
	}
}

func TestConcurrencyLimiter_AllowsAfterRelease(t *testing.T) {
	cl := memory.NewConcurrencyLimiter(domain.ConcurrencyRule{MaxInFlight: 1})
	cl.Acquire("client")
	cl.Release("client")
	if !cl.Acquire("client") {
		t.Fatal("Acquire should succeed after Release")
	}
}

func TestConcurrencyLimiter_IndependentKeys(t *testing.T) {
	cl := memory.NewConcurrencyLimiter(domain.ConcurrencyRule{MaxInFlight: 1})
	if !cl.Acquire("a") {
		t.Fatal("a should acquire")
	}
	if !cl.Acquire("b") {
		t.Fatal("b should acquire — independent counter")
	}
	if cl.Acquire("a") {
		t.Fatal("a's second Acquire should be denied")
	}
}

func TestConcurrencyLimiter_ReleaseDoesNotGoBelowZero(t *testing.T) {
	cl := memory.NewConcurrencyLimiter(domain.ConcurrencyRule{MaxInFlight: 1})
	cl.Release("client") // spurious release — must not panic
	if !cl.Acquire("client") {
		t.Fatal("Acquire after spurious Release should still work")
	}
}

func BenchmarkConcurrencyLimiter_AcquireRelease_SingleKey(b *testing.B) {
	cl := memory.NewConcurrencyLimiter(domain.ConcurrencyRule{MaxInFlight: 1})
	b.ResetTimer()
	for range b.N {
		cl.Acquire("client")
		cl.Release("client")
	}
}

func BenchmarkConcurrencyLimiter_AcquireRelease_HighCardinality(b *testing.B) {
	const keys = 1000
	cl := memory.NewConcurrencyLimiter(domain.ConcurrencyRule{MaxInFlight: 1})
	k := make([]string, keys)
	for i := range keys {
		k[i] = fmt.Sprintf("client-%d", i)
	}
	b.ResetTimer()
	for i := range b.N {
		key := k[i%keys]
		cl.Acquire(key)
		cl.Release(key)
	}
}
