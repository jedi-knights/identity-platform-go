//go:build unit

package memory_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func TestClientAssertionReplayRepository_MarkUsed_FirstCallSucceeds(t *testing.T) {
	// Arrange
	repo := memory.NewClientAssertionReplayRepository()

	// Act
	err := repo.MarkUsed(context.Background(), "jti-1", time.Now().Add(time.Minute))

	// Assert
	if err != nil {
		t.Fatalf("MarkUsed: %v", err)
	}
}

func TestClientAssertionReplayRepository_MarkUsed_SecondCallReplayed(t *testing.T) {
	// Arrange — the load-bearing invariant: a jti recorded once must be
	// rejected on every subsequent call for the same jti.
	repo := memory.NewClientAssertionReplayRepository()
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

func TestClientAssertionReplayRepository_MarkUsed_ExpiredEntryCanBeReused(t *testing.T) {
	// Arrange — a jti whose TTL has elapsed is not remembered forever;
	// once the entry lazily expires, the same jti is accepted again.
	// (A real client would never legitimately reuse a jti after its
	// assertion's own exp has passed — the assertion itself would be
	// rejected first — this only confirms the store does not grow
	// unbounded.)
	repo := memory.NewClientAssertionReplayRepository()
	if err := repo.MarkUsed(context.Background(), "jti-expired", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("first MarkUsed: %v", err)
	}

	// Act
	err := repo.MarkUsed(context.Background(), "jti-expired", time.Now().Add(time.Minute))

	// Assert
	if err != nil {
		t.Errorf("MarkUsed after expiry err = %v, want nil", err)
	}
}

func TestClientAssertionReplayRepository_ConcurrentMarkUsed_OnlyOneSucceeds(t *testing.T) {
	// Arrange — N goroutines race to mark the same jti; exactly one must
	// succeed.
	const racers = 32
	repo := memory.NewClientAssertionReplayRepository()

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
		t.Errorf("got %d successful MarkUsed calls, want exactly 1", got)
	}
}
