//go:build unit

package redis_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	redisadapter "github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/adapters/outbound/redis"
)

func newTestClient(t *testing.T, mr *miniredis.Miniredis) *goredis.Client {
	t.Helper()
	return goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
}

func TestRevocationStore_IsActive_KeyExists(t *testing.T) {
	mr := miniredis.RunT(t)
	client := newTestClient(t, mr)

	raw := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.payload"
	mr.Set("token:"+raw, "1")

	store := redisadapter.NewRevocationStore(client)
	active, err := store.IsActive(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !active {
		t.Error("expected active=true when key exists, got false")
	}
}

func TestRevocationStore_IsActive_KeyMissing(t *testing.T) {
	mr := miniredis.RunT(t)
	client := newTestClient(t, mr)

	raw := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.missing"

	store := redisadapter.NewRevocationStore(client)
	active, err := store.IsActive(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if active {
		t.Error("expected active=false when key is missing, got true")
	}
}

// TestRevocationStore_IsActive_RedisUnavailable confirms fail-closed behaviour:
// when Redis is unreachable, IsActive returns an error so the caller can treat
// the token as inactive (security takes precedence over availability).
func TestRevocationStore_IsActive_RedisUnavailable(t *testing.T) {
	// Point the client at a port that is not listening.
	client := goredis.NewClient(&goredis.Options{
		Addr:        "localhost:1", // port 1 is reserved and never bound
		DialTimeout: 50 * time.Millisecond,
	})

	raw := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.unreachable"
	store := redisadapter.NewRevocationStore(client)
	active, err := store.IsActive(context.Background(), raw)
	if err == nil {
		t.Error("expected error when Redis is unavailable, got nil")
	}
	if active {
		t.Error("expected active=false on error (fail-closed), got true")
	}
}

func TestRevocationStore_IsActive_KeyExpired(t *testing.T) {
	mr := miniredis.RunT(t)
	client := newTestClient(t, mr)

	raw := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.expired"
	mr.Set("token:"+raw, "1")
	mr.SetTTL("token:"+raw, 1*time.Second)

	// Fast-forward miniredis time past the TTL so the key expires.
	mr.FastForward(2 * time.Second)

	store := redisadapter.NewRevocationStore(client)
	active, err := store.IsActive(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if active {
		t.Error("expected active=false for expired key, got true")
	}
}
