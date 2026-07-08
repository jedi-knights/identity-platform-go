//go:build unit

package redis_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/redis"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func newDPoPTestServer(t *testing.T) (*miniredis.Miniredis, *goredis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	return mr, client
}

func TestDPoPProofRepository_Redis_MarkUsed_FirstUseSucceeds(t *testing.T) {
	// Arrange
	_, client := newDPoPTestServer(t)
	repo := redis.NewDPoPProofRepository(client)

	// Act
	err := repo.MarkUsed(context.Background(), "jti-1", time.Now().Add(time.Minute))

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDPoPProofRepository_Redis_MarkUsed_ReplayWithinWindowFails(t *testing.T) {
	// Arrange
	_, client := newDPoPTestServer(t)
	repo := redis.NewDPoPProofRepository(client)
	expiresAt := time.Now().Add(time.Minute)
	if err := repo.MarkUsed(context.Background(), "jti-1", expiresAt); err != nil {
		t.Fatalf("unexpected error on first use: %v", err)
	}

	// Act
	err := repo.MarkUsed(context.Background(), "jti-1", expiresAt)

	// Assert
	if !errors.Is(err, domain.ErrDPoPProofReplayed) {
		t.Errorf("expected ErrDPoPProofReplayed, got: %v", err)
	}
}

func TestDPoPProofRepository_Redis_MarkUsed_ReplayAfterExpirySucceeds(t *testing.T) {
	// Arrange
	mr, client := newDPoPTestServer(t)
	repo := redis.NewDPoPProofRepository(client)
	if err := repo.MarkUsed(context.Background(), "jti-1", time.Now().Add(time.Second)); err != nil {
		t.Fatalf("unexpected error on first use: %v", err)
	}
	mr.FastForward(2 * time.Second)

	// Act
	err := repo.MarkUsed(context.Background(), "jti-1", time.Now().Add(time.Minute))

	// Assert
	if err != nil {
		t.Errorf("expected reuse of an expired jti to succeed, got: %v", err)
	}
}

func TestDPoPProofRepository_Redis_MarkUsed_DistinctJTIsDoNotCollide(t *testing.T) {
	// Arrange
	_, client := newDPoPTestServer(t)
	repo := redis.NewDPoPProofRepository(client)
	expiresAt := time.Now().Add(time.Minute)
	if err := repo.MarkUsed(context.Background(), "jti-1", expiresAt); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Act
	err := repo.MarkUsed(context.Background(), "jti-2", expiresAt)

	// Assert
	if err != nil {
		t.Errorf("expected a distinct jti to succeed, got: %v", err)
	}
}
