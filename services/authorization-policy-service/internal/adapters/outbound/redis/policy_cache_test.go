//go:build unit

package redis_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	redisadapter "github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/outbound/redis"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/ports"
)

// newPolicyTestClient starts an in-process miniredis server and returns a connected
// go-redis client. The server is shut down automatically via t.Cleanup.
func newPolicyTestClient(t *testing.T) *goredis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	return goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
}

// fakeEvaluator is a test double for ports.PolicyEvaluator.
type fakeEvaluator struct {
	resp *domain.EvaluationResponse
	err  error
	calls int
}

func (f *fakeEvaluator) Evaluate(_ context.Context, _ domain.EvaluationRequest) (*domain.EvaluationResponse, error) {
	f.calls++
	return f.resp, f.err
}

var _ ports.PolicyEvaluator = (*fakeEvaluator)(nil)

// TestCacheKey_ColonInFieldDoesNotCollide verifies that a subjectID or resource
// containing a colon does not collide with a different subject/resource combination.
// e.g. subject="a:b", resource="c" must differ from subject="a", resource="b:c".
func TestCacheKey_ColonInFieldDoesNotCollide(t *testing.T) {
	key1 := redisadapter.CacheKey("a:b", "c", "read")
	key2 := redisadapter.CacheKey("a", "b:c", "read")
	if key1 == key2 {
		t.Errorf("key collision: subject 'a:b'/resource 'c' produced same key as subject 'a'/resource 'b:c': %q", key1)
	}
}

// TestCacheKey_Stable verifies that the same inputs always produce the same key.
func TestCacheKey_Stable(t *testing.T) {
	k1 := redisadapter.CacheKey("user-123", "articles", "read")
	k2 := redisadapter.CacheKey("user-123", "articles", "read")
	if k1 != k2 {
		t.Errorf("cache key is not stable: %q != %q", k1, k2)
	}
}

// TestEncodeCacheValue_PreservesReason verifies that encoding then decoding an
// EvaluationResponse round-trips the Reason field (which was silently dropped
// when the cache stored only "1"/"0").
func TestEncodeCacheValue_PreservesReason(t *testing.T) {
	tests := []struct {
		name string
		resp *domain.EvaluationResponse
	}{
		{
			name: "allowed response",
			resp: &domain.EvaluationResponse{Allowed: true},
		},
		{
			name: "denied with reason",
			resp: &domain.EvaluationResponse{Allowed: false, Reason: "insufficient permissions"},
		},
		{
			name: "denied no policy",
			resp: &domain.EvaluationResponse{Allowed: false, Reason: "no policy found for subject"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := redisadapter.EncodeCacheValue(tt.resp)
			got, err := redisadapter.DecodeCacheValue(encoded)
			if err != nil {
				t.Fatalf("DecodeCacheValue(%q) error: %v", encoded, err)
			}
			if got.Allowed != tt.resp.Allowed {
				t.Errorf("Allowed = %v, want %v", got.Allowed, tt.resp.Allowed)
			}
			if got.Reason != tt.resp.Reason {
				t.Errorf("Reason = %q, want %q", got.Reason, tt.resp.Reason)
			}
		})
	}
}

// --- CachingPolicyEvaluator.Evaluate ---

func TestCachingPolicyEvaluator_Evaluate_CacheMiss_WritesBack(t *testing.T) {
	client := newPolicyTestClient(t)
	inner := &fakeEvaluator{resp: &domain.EvaluationResponse{Allowed: true, Reason: "ok"}}
	evaluator := redisadapter.NewCachingPolicyEvaluator(inner, client, time.Minute, logging.NewLogger(logging.Config{Output: io.Discard}))

	req := domain.EvaluationRequest{SubjectID: "user-1", Resource: "doc", Action: "read"}

	got, err := evaluator.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !got.Allowed {
		t.Errorf("Allowed = false, want true")
	}
	if inner.calls != 1 {
		t.Errorf("inner called %d times, want 1", inner.calls)
	}

	// Second call should hit cache — inner should not be called again.
	got2, err := evaluator.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("second Evaluate: %v", err)
	}
	if !got2.Allowed {
		t.Errorf("cached Allowed = false, want true")
	}
	if inner.calls != 1 {
		t.Errorf("inner called %d times after cache hit, want 1", inner.calls)
	}
}

func TestCachingPolicyEvaluator_Evaluate_InnerError_Propagates(t *testing.T) {
	client := newPolicyTestClient(t)
	inner := &fakeEvaluator{err: errors.New("policy store unavailable")}
	evaluator := redisadapter.NewCachingPolicyEvaluator(inner, client, time.Minute, logging.NewLogger(logging.Config{Output: io.Discard}))

	req := domain.EvaluationRequest{SubjectID: "user-1", Resource: "doc", Action: "read"}

	_, err := evaluator.Evaluate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from inner evaluator, got nil")
	}
}

func TestCachingPolicyEvaluator_Evaluate_RedisUnavailable_FallsThrough(t *testing.T) {
	// Start miniredis, connect, then close it so all subsequent Redis ops fail immediately.
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	mr.Close() // shut down after the client is created — ops will fail without a slow dial

	inner := &fakeEvaluator{resp: &domain.EvaluationResponse{Allowed: false, Reason: "denied"}}
	evaluator := redisadapter.NewCachingPolicyEvaluator(inner, client, time.Minute, logging.NewLogger(logging.Config{Output: io.Discard}))

	req := domain.EvaluationRequest{SubjectID: "user-1", Resource: "doc", Action: "read"}

	got, err := evaluator.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// Redis is down; the decorator must fall through and return the inner result.
	if got.Allowed {
		t.Error("Allowed = true, want false (inner response)")
	}
	if inner.calls != 1 {
		t.Errorf("inner called %d times, want 1", inner.calls)
	}
}

func TestCachingPolicyEvaluator_Evaluate_CorruptCacheData_FallsThrough(t *testing.T) {
	// Seed corrupt data at the cache key before the first Evaluate call.
	// The decorator must fall through to inner rather than erroring.
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})

	req := domain.EvaluationRequest{SubjectID: "user-1", Resource: "doc", Action: "read"}
	key := redisadapter.CacheKey(req.SubjectID, req.Resource, req.Action)
	if err := mr.Set(key, "not-valid-json"); err != nil {
		t.Fatalf("seeding corrupt key: %v", err)
	}

	inner := &fakeEvaluator{resp: &domain.EvaluationResponse{Allowed: true, Reason: "ok"}}
	evaluator := redisadapter.NewCachingPolicyEvaluator(inner, client, time.Minute, logging.NewLogger(logging.Config{Output: io.Discard}))

	got, err := evaluator.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// Corrupt cache data must be treated like a miss — fall through to inner.
	if !got.Allowed {
		t.Error("Allowed = false, want true (inner response after corrupt cache miss)")
	}
	if inner.calls != 1 {
		t.Errorf("inner called %d times, want 1", inner.calls)
	}
}
