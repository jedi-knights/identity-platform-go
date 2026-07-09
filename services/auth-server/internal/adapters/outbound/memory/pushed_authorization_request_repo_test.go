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

func newTestPAR(requestURI string, expIn time.Duration) *domain.PushedAuthorizationRequest {
	return &domain.PushedAuthorizationRequest{
		RequestURI:          requestURI,
		ClientID:            "client-a",
		ResponseType:        "code",
		RedirectURI:         "https://rp.example.com/cb",
		Scope:               "read",
		CodeChallenge:       "challenge-value",
		CodeChallengeMethod: "S256",
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(expIn),
	}
}

func TestPushedAuthorizationRequestRepository_SaveThenConsume(t *testing.T) {
	// Arrange
	repo := memory.NewPushedAuthorizationRequestRepository()
	req := newTestPAR("urn:ietf:params:oauth:request_uri:abc", time.Minute)

	// Act
	if err := repo.Save(context.Background(), req); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := repo.Consume(context.Background(), "urn:ietf:params:oauth:request_uri:abc")

	// Assert
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.ClientID != "client-a" {
		t.Errorf("ClientID = %q, want %q", got.ClientID, "client-a")
	}
}

func TestPushedAuthorizationRequestRepository_ConsumeIsAtomicReadAndDelete(t *testing.T) {
	// Arrange — second Consume after a successful one must return NotFound.
	repo := memory.NewPushedAuthorizationRequestRepository()
	if err := repo.Save(context.Background(), newTestPAR("uri-once", time.Minute)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := repo.Consume(context.Background(), "uri-once"); err != nil {
		t.Fatalf("first Consume: %v", err)
	}

	// Act
	_, err := repo.Consume(context.Background(), "uri-once")

	// Assert
	if !errors.Is(err, domain.ErrPushedAuthorizationRequestNotFound) {
		t.Errorf("second Consume err = %v, want ErrPushedAuthorizationRequestNotFound", err)
	}
}

func TestPushedAuthorizationRequestRepository_ConsumeUnknown(t *testing.T) {
	// Arrange
	repo := memory.NewPushedAuthorizationRequestRepository()

	// Act
	_, err := repo.Consume(context.Background(), "never-saved")

	// Assert
	if !errors.Is(err, domain.ErrPushedAuthorizationRequestNotFound) {
		t.Errorf("err = %v, want ErrPushedAuthorizationRequestNotFound", err)
	}
}

func TestPushedAuthorizationRequestRepository_ConsumeExpired(t *testing.T) {
	// Arrange
	repo := memory.NewPushedAuthorizationRequestRepository()
	if err := repo.Save(context.Background(), newTestPAR("uri-expired", -time.Second)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	_, err := repo.Consume(context.Background(), "uri-expired")

	// Assert
	if !errors.Is(err, domain.ErrPushedAuthorizationRequestNotFound) {
		t.Errorf("err = %v, want ErrPushedAuthorizationRequestNotFound for expired request", err)
	}
}

func TestPushedAuthorizationRequestRepository_ConcurrentConsumeOnlyOneSucceeds(t *testing.T) {
	// Arrange
	const racers = 32
	repo := memory.NewPushedAuthorizationRequestRepository()
	if err := repo.Save(context.Background(), newTestPAR("uri-race", time.Minute)); err != nil {
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
			if _, err := repo.Consume(context.Background(), "uri-race"); err == nil {
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
