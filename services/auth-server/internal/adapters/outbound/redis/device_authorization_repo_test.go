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

func newDeviceAuthTestServer(t *testing.T) (*miniredis.Miniredis, *goredis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	return mr, client
}

func newDeviceAuth(deviceCode, userCode string, expIn time.Duration) *domain.DeviceAuthorization {
	return &domain.DeviceAuthorization{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   "client-a",
		Scope:      "read",
		Status:     domain.DeviceAuthorizationPending,
		Interval:   5,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(expIn),
	}
}

func TestDeviceAuthorizationRepository_Redis_SaveThenFindByDeviceCode(t *testing.T) {
	// Arrange
	_, client := newDeviceAuthTestServer(t)
	repo := redis.NewDeviceAuthorizationRepository(client)
	auth := newDeviceAuth("device-a", "USER-A", time.Minute)

	// Act
	if err := repo.Save(context.Background(), auth); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := repo.FindByDeviceCode(context.Background(), "device-a")

	// Assert
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if got.ClientID != "client-a" {
		t.Errorf("ClientID = %q, want %q", got.ClientID, "client-a")
	}
}

func TestDeviceAuthorizationRepository_Redis_FindByUserCode(t *testing.T) {
	// Arrange
	_, client := newDeviceAuthTestServer(t)
	repo := redis.NewDeviceAuthorizationRepository(client)
	if err := repo.Save(context.Background(), newDeviceAuth("device-b", "USER-B", time.Minute)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	got, err := repo.FindByUserCode(context.Background(), "USER-B")

	// Assert
	if err != nil {
		t.Fatalf("FindByUserCode: %v", err)
	}
	if got.DeviceCode != "device-b" {
		t.Errorf("DeviceCode = %q, want %q", got.DeviceCode, "device-b")
	}
}

func TestDeviceAuthorizationRepository_Redis_FindByUserCodeUnknown(t *testing.T) {
	// Arrange
	_, client := newDeviceAuthTestServer(t)
	repo := redis.NewDeviceAuthorizationRepository(client)

	// Act
	_, err := repo.FindByUserCode(context.Background(), "never-saved")

	// Assert
	if !errors.Is(err, domain.ErrDeviceAuthorizationNotFound) {
		t.Errorf("err = %v, want ErrDeviceAuthorizationNotFound", err)
	}
}

func TestDeviceAuthorizationRepository_Redis_ApproveThenConsume(t *testing.T) {
	// Arrange
	_, client := newDeviceAuthTestServer(t)
	repo := redis.NewDeviceAuthorizationRepository(client)
	if err := repo.Save(context.Background(), newDeviceAuth("device-c", "USER-C", time.Minute)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	if err := repo.Approve(context.Background(), "USER-C", "subject-1"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	got, err := repo.Consume(context.Background(), "device-c")

	// Assert
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.Status != domain.DeviceAuthorizationApproved {
		t.Errorf("Status = %q, want approved", got.Status)
	}
	if got.Subject != "subject-1" {
		t.Errorf("Subject = %q, want %q", got.Subject, "subject-1")
	}
}

func TestDeviceAuthorizationRepository_Redis_Deny(t *testing.T) {
	// Arrange
	_, client := newDeviceAuthTestServer(t)
	repo := redis.NewDeviceAuthorizationRepository(client)
	if err := repo.Save(context.Background(), newDeviceAuth("device-d", "USER-D", time.Minute)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	if err := repo.Deny(context.Background(), "USER-D"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	got, err := repo.FindByDeviceCode(context.Background(), "device-d")

	// Assert
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if got.Status != domain.DeviceAuthorizationDenied {
		t.Errorf("Status = %q, want denied", got.Status)
	}
}

func TestDeviceAuthorizationRepository_Redis_ApproveUnknownUserCode(t *testing.T) {
	// Arrange
	_, client := newDeviceAuthTestServer(t)
	repo := redis.NewDeviceAuthorizationRepository(client)

	// Act
	err := repo.Approve(context.Background(), "never-saved", "subject-1")

	// Assert
	if !errors.Is(err, domain.ErrDeviceAuthorizationNotFound) {
		t.Errorf("err = %v, want ErrDeviceAuthorizationNotFound", err)
	}
}

func TestDeviceAuthorizationRepository_Redis_ConsumeIsAtomic(t *testing.T) {
	// Arrange
	_, client := newDeviceAuthTestServer(t)
	repo := redis.NewDeviceAuthorizationRepository(client)
	if err := repo.Save(context.Background(), newDeviceAuth("device-once", "USER-ONCE", time.Minute)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := repo.Consume(context.Background(), "device-once"); err != nil {
		t.Fatalf("first Consume: %v", err)
	}

	// Act
	_, err := repo.Consume(context.Background(), "device-once")

	// Assert
	if !errors.Is(err, domain.ErrDeviceAuthorizationNotFound) {
		t.Errorf("second Consume err = %v, want ErrDeviceAuthorizationNotFound", err)
	}
}

func TestDeviceAuthorizationRepository_Redis_ConsumeUnknown(t *testing.T) {
	// Arrange
	_, client := newDeviceAuthTestServer(t)
	repo := redis.NewDeviceAuthorizationRepository(client)

	// Act
	_, err := repo.Consume(context.Background(), "never-saved")

	// Assert
	if !errors.Is(err, domain.ErrDeviceAuthorizationNotFound) {
		t.Errorf("err = %v, want ErrDeviceAuthorizationNotFound", err)
	}
}

func TestDeviceAuthorizationRepository_Redis_TTLAlignedToExpiry(t *testing.T) {
	// Arrange
	mr, client := newDeviceAuthTestServer(t)
	repo := redis.NewDeviceAuthorizationRepository(client)
	if err := repo.Save(context.Background(), newDeviceAuth("device-ttl", "USER-TTL", 5*time.Second)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	mr.FastForward(10 * time.Second)
	_, err := repo.FindByDeviceCode(context.Background(), "device-ttl")

	// Assert
	if !errors.Is(err, domain.ErrDeviceAuthorizationNotFound) {
		t.Errorf("post-TTL FindByDeviceCode err = %v, want ErrDeviceAuthorizationNotFound", err)
	}
}

func TestDeviceAuthorizationRepository_Redis_FindByUserCodeAfterConsumeIsGone(t *testing.T) {
	// Arrange
	_, client := newDeviceAuthTestServer(t)
	repo := redis.NewDeviceAuthorizationRepository(client)
	if err := repo.Save(context.Background(), newDeviceAuth("device-idx", "USER-IDX", time.Minute)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := repo.Consume(context.Background(), "device-idx"); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	// Act
	_, err := repo.FindByUserCode(context.Background(), "USER-IDX")

	// Assert
	if !errors.Is(err, domain.ErrDeviceAuthorizationNotFound) {
		t.Errorf("err = %v, want ErrDeviceAuthorizationNotFound after Consume", err)
	}
}

func TestDeviceAuthorizationRepository_Redis_ConcurrentConsumeAtomic(t *testing.T) {
	// Arrange
	const racers = 32
	_, client := newDeviceAuthTestServer(t)
	repo := redis.NewDeviceAuthorizationRepository(client)
	if err := repo.Save(context.Background(), newDeviceAuth("device-race", "USER-RACE", time.Minute)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var successes atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func() {
			defer wg.Done()
			<-start
			if _, err := repo.Consume(context.Background(), "device-race"); err == nil {
				successes.Add(1)
			}
		}()
	}

	// Act
	close(start)
	wg.Wait()

	// Assert
	if got := successes.Load(); got != 1 {
		t.Errorf("got %d successful Consume calls under race, want exactly 1", got)
	}
}
