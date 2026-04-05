package redis_test

import (
	"testing"

	redisadapter "github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/outbound/redis"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

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
