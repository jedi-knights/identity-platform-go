//go:build unit

package redis_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/redis"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func newReplayTestServer(t *testing.T) (*miniredis.Miniredis, *goredis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	return mr, client
}

func TestClientAssertionReplayRepository_Redis_MarkUsed_FirstCallSucceeds(t *testing.T) {
	// Arrange
	_, client := newReplayTestServer(t)
	repo := redis.NewClientAssertionReplayRepository(client)

	// Act
	err := repo.MarkUsed(context.Background(), "jti-1", time.Now().Add(time.Minute))

	// Assert
	if err != nil {
		t.Fatalf("MarkUsed: %v", err)
	}
}

func TestClientAssertionReplayRepository_Redis_MarkUsed_SecondCallReplayed(t *testing.T) {
	// Arrange
	_, client := newReplayTestServer(t)
	repo := redis.NewClientAssertionReplayRepository(client)
	if err := repo.MarkUsed(context.Background(), "jti-once", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("first MarkUsed: %v", err)
	}

	// Act
	err := repo.MarkUsed(context.Background(), "jti-once", time.Now().Add(time.Minute))

	// Assert
	if !errors.Is(err, domain.ErrClientAssertionReplayed) {
		t.Errorf("second MarkUsed err = %v, want ErrClientAssertionReplayed", err)
	}
}

func TestClientAssertionReplayRepository_Redis_TTLAlignedToExpiry(t *testing.T) {
	// Arrange — miniredis's virtual clock, advanced via FastForward, avoids
	// wall-clock flakiness.
	mr, client := newReplayTestServer(t)
	repo := redis.NewClientAssertionReplayRepository(client)
	if err := repo.MarkUsed(context.Background(), "jti-ttl", time.Now().Add(5*time.Second)); err != nil {
		t.Fatalf("first MarkUsed: %v", err)
	}

	// Act — past the TTL, the same jti must be accepted again (the key
	// expired out of Redis).
	mr.FastForward(10 * time.Second)
	err := repo.MarkUsed(context.Background(), "jti-ttl", time.Now().Add(time.Minute))

	// Assert
	if err != nil {
		t.Errorf("post-TTL MarkUsed err = %v, want nil", err)
	}
}

func TestClientAssertionReplayRepository_Redis_ConcurrentMarkUsed_OnlyOneSucceeds(t *testing.T) {
	// Arrange
	const racers = 32
	_, client := newReplayTestServer(t)
	repo := redis.NewClientAssertionReplayRepository(client)

	var successes atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func() {
			defer wg.Done()
			<-start
			if err := repo.MarkUsed(context.Background(), "jti-race", time.Now().Add(time.Minute)); err == nil {
				successes.Add(1)
			}
		}()
	}

	// Act
	close(start)
	wg.Wait()

	// Assert
	if got := successes.Load(); got != 1 {
		t.Errorf("got %d successful MarkUsed calls under race, want exactly 1", got)
	}
}
