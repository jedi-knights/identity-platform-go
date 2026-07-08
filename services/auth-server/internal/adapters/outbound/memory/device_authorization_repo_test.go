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

func newTestDeviceAuth(deviceCode, userCode string, expIn time.Duration) *domain.DeviceAuthorization {
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

func TestDeviceAuthorizationRepository_SaveThenFindByDeviceCode(t *testing.T) {
	// Arrange
	repo := memory.NewDeviceAuthorizationRepository()
	auth := newTestDeviceAuth("device-abc", "USER-CODE", time.Minute)

	// Act
	if err := repo.Save(context.Background(), auth); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := repo.FindByDeviceCode(context.Background(), "device-abc")

	// Assert
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if got.ClientID != "client-a" {
		t.Errorf("ClientID = %q, want %q", got.ClientID, "client-a")
	}
}

func TestDeviceAuthorizationRepository_FindByDeviceCodeDoesNotDelete(t *testing.T) {
	// Arrange — polling must be able to observe "still pending" repeatedly.
	repo := memory.NewDeviceAuthorizationRepository()
	if err := repo.Save(context.Background(), newTestDeviceAuth("device-poll", "USER-POLL", time.Minute)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	_, err1 := repo.FindByDeviceCode(context.Background(), "device-poll")
	_, err2 := repo.FindByDeviceCode(context.Background(), "device-poll")

	// Assert
	if err1 != nil || err2 != nil {
		t.Fatalf("expected two successful lookups, got %v, %v", err1, err2)
	}
}

func TestDeviceAuthorizationRepository_FindByUserCode(t *testing.T) {
	// Arrange
	repo := memory.NewDeviceAuthorizationRepository()
	if err := repo.Save(context.Background(), newTestDeviceAuth("device-xyz", "USER-XYZ", time.Minute)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	got, err := repo.FindByUserCode(context.Background(), "USER-XYZ")

	// Assert
	if err != nil {
		t.Fatalf("FindByUserCode: %v", err)
	}
	if got.DeviceCode != "device-xyz" {
		t.Errorf("DeviceCode = %q, want %q", got.DeviceCode, "device-xyz")
	}
}

func TestDeviceAuthorizationRepository_FindByUserCodeUnknown(t *testing.T) {
	// Arrange
	repo := memory.NewDeviceAuthorizationRepository()

	// Act
	_, err := repo.FindByUserCode(context.Background(), "never-saved")

	// Assert
	if !errors.Is(err, domain.ErrDeviceAuthorizationNotFound) {
		t.Errorf("err = %v, want ErrDeviceAuthorizationNotFound", err)
	}
}

func TestDeviceAuthorizationRepository_ApproveThenConsume(t *testing.T) {
	// Arrange
	repo := memory.NewDeviceAuthorizationRepository()
	if err := repo.Save(context.Background(), newTestDeviceAuth("device-app", "USER-APP", time.Minute)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	if err := repo.Approve(context.Background(), "USER-APP", "subject-1"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	got, err := repo.Consume(context.Background(), "device-app")

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

func TestDeviceAuthorizationRepository_Deny(t *testing.T) {
	// Arrange
	repo := memory.NewDeviceAuthorizationRepository()
	if err := repo.Save(context.Background(), newTestDeviceAuth("device-den", "USER-DEN", time.Minute)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	if err := repo.Deny(context.Background(), "USER-DEN"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	got, err := repo.FindByDeviceCode(context.Background(), "device-den")

	// Assert
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if got.Status != domain.DeviceAuthorizationDenied {
		t.Errorf("Status = %q, want denied", got.Status)
	}
}

func TestDeviceAuthorizationRepository_ApproveUnknownUserCode(t *testing.T) {
	// Arrange
	repo := memory.NewDeviceAuthorizationRepository()

	// Act
	err := repo.Approve(context.Background(), "never-saved", "subject-1")

	// Assert
	if !errors.Is(err, domain.ErrDeviceAuthorizationNotFound) {
		t.Errorf("err = %v, want ErrDeviceAuthorizationNotFound", err)
	}
}

func TestDeviceAuthorizationRepository_DenyUnknownUserCode(t *testing.T) {
	// Arrange
	repo := memory.NewDeviceAuthorizationRepository()

	// Act
	err := repo.Deny(context.Background(), "never-saved")

	// Assert
	if !errors.Is(err, domain.ErrDeviceAuthorizationNotFound) {
		t.Errorf("err = %v, want ErrDeviceAuthorizationNotFound", err)
	}
}

func TestDeviceAuthorizationRepository_ConsumeIsAtomicReadAndDelete(t *testing.T) {
	// Arrange — second Consume after a successful one must return NotFound.
	repo := memory.NewDeviceAuthorizationRepository()
	if err := repo.Save(context.Background(), newTestDeviceAuth("device-once", "USER-ONCE", time.Minute)); err != nil {
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

func TestDeviceAuthorizationRepository_ConsumeUnknownDeviceCode(t *testing.T) {
	// Arrange
	repo := memory.NewDeviceAuthorizationRepository()

	// Act
	_, err := repo.Consume(context.Background(), "never-saved")

	// Assert
	if !errors.Is(err, domain.ErrDeviceAuthorizationNotFound) {
		t.Errorf("err = %v, want ErrDeviceAuthorizationNotFound", err)
	}
}

func TestDeviceAuthorizationRepository_ConsumeExpired(t *testing.T) {
	// Arrange — already-expired record: Consume must report NotFound.
	repo := memory.NewDeviceAuthorizationRepository()
	if err := repo.Save(context.Background(), newTestDeviceAuth("device-exp", "USER-EXP", -time.Second)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	_, err := repo.Consume(context.Background(), "device-exp")

	// Assert
	if !errors.Is(err, domain.ErrDeviceAuthorizationNotFound) {
		t.Errorf("err = %v, want ErrDeviceAuthorizationNotFound for expired record", err)
	}
}

func TestDeviceAuthorizationRepository_FindByUserCodeAfterConsumeIsGone(t *testing.T) {
	// Arrange — Consume must remove both the device_code entry and the
	// user_code index, or the verification page could resurrect a
	// consumed request.
	repo := memory.NewDeviceAuthorizationRepository()
	if err := repo.Save(context.Background(), newTestDeviceAuth("device-idx", "USER-IDX", time.Minute)); err != nil {
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

func TestDeviceAuthorizationRepository_ConcurrentConsumeOnlyOneSucceeds(t *testing.T) {
	// Arrange — N goroutines race to Consume the same device_code; exactly
	// one must succeed.
	const racers = 32
	repo := memory.NewDeviceAuthorizationRepository()
	if err := repo.Save(context.Background(), newTestDeviceAuth("device-race", "USER-RACE", time.Minute)); err != nil {
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
		t.Errorf("got %d successful Consume calls, want exactly 1", got)
	}
}
