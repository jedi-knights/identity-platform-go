//go:build unit

package memory_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

func entry(body string) *ports.CacheEntry {
	return &ports.CacheEntry{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       []byte(body),
	}
}

func TestCache_GetMissOnEmpty(t *testing.T) {
	c := memory.NewCache(10)
	_, ok := c.Get("key")
	if ok {
		t.Fatal("expected miss on empty cache")
	}
}

func TestCache_SetAndGet(t *testing.T) {
	c := memory.NewCache(10)
	c.Set("k", entry("hello"), time.Minute)
	got, ok := c.Get("k")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(got.Body) != "hello" {
		t.Errorf("body: got %q, want %q", got.Body, "hello")
	}
}

func TestCache_GetMissAfterTTLExpiry(t *testing.T) {
	c := memory.NewCache(10)
	c.Set("k", entry("x"), time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	_, ok := c.Get("k")
	if ok {
		t.Fatal("expected miss after TTL expiry")
	}
}

func TestCache_SetWithZeroTTLIsNoop(t *testing.T) {
	c := memory.NewCache(10)
	c.Set("k", entry("x"), 0)
	_, ok := c.Get("k")
	if ok {
		t.Fatal("zero TTL should not store the entry")
	}
}

func TestCache_SetWithNegativeTTLIsNoop(t *testing.T) {
	c := memory.NewCache(10)
	c.Set("k", entry("x"), -1)
	_, ok := c.Get("k")
	if ok {
		t.Fatal("negative TTL should not store the entry")
	}
}

func TestCache_LRUEviction(t *testing.T) {
	c := memory.NewCache(2)
	c.Set("a", entry("a"), time.Minute)
	c.Set("b", entry("b"), time.Minute)
	// Access "a" so "b" becomes LRU.
	c.Get("a")
	// Adding "c" should evict "b" (LRU).
	c.Set("c", entry("c"), time.Minute)

	_, okA := c.Get("a")
	_, okB := c.Get("b")
	_, okC := c.Get("c")

	if !okA {
		t.Error("expected 'a' to remain (was recently accessed)")
	}
	if okB {
		t.Error("expected 'b' to be evicted (LRU)")
	}
	if !okC {
		t.Error("expected 'c' to be present")
	}
}

func TestCache_UpdateExistingKey(t *testing.T) {
	c := memory.NewCache(10)
	c.Set("k", entry("first"), time.Minute)
	c.Set("k", entry("second"), time.Minute)
	got, ok := c.Get("k")
	if !ok {
		t.Fatal("expected cache hit after update")
	}
	if string(got.Body) != "second" {
		t.Errorf("body after update: got %q, want %q", got.Body, "second")
	}
}

func TestCache_DefaultMaxEntries(t *testing.T) {
	// NewCache(0) should default to 1000 — smoke test that it doesn't panic.
	c := memory.NewCache(0)
	c.Set("k", entry("v"), time.Minute)
	if _, ok := c.Get("k"); !ok {
		t.Fatal("expected hit in default-size cache")
	}
}
