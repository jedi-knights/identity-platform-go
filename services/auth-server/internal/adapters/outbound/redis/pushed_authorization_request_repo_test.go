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

func newPARTestServer(t *testing.T) (*miniredis.Miniredis, *goredis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	return mr, client
}

func newPAR(requestURI string, expIn time.Duration) *domain.PushedAuthorizationRequest {
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

func TestPushedAuthorizationRequestRepository_Redis_SaveThenConsume(t *testing.T) {
	// Arrange
	_, client := newPARTestServer(t)
	repo := redis.NewPushedAuthorizationRequestRepository(client)
	req := newPAR("uri-a", time.Minute)

	// Act
	if err := repo.Save(context.Background(), req); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := repo.Consume(context.Background(), "uri-a")

	// Assert
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.ClientID != "client-a" {
		t.Errorf("ClientID = %q, want %q", got.ClientID, "client-a")
	}
}

func TestPushedAuthorizationRequestRepository_Redis_ConsumeIsAtomic(t *testing.T) {
	// Arrange
	_, client := newPARTestServer(t)
	repo := redis.NewPushedAuthorizationRequestRepository(client)
	if err := repo.Save(context.Background(), newPAR("uri-once", time.Minute)); err != nil {
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

func TestPushedAuthorizationRequestRepository_Redis_ConsumeUnknown(t *testing.T) {
	// Arrange
	_, client := newPARTestServer(t)
	repo := redis.NewPushedAuthorizationRequestRepository(client)

	// Act
	_, err := repo.Consume(context.Background(), "never-saved")

	// Assert
	if !errors.Is(err, domain.ErrPushedAuthorizationRequestNotFound) {
		t.Errorf("err = %v, want ErrPushedAuthorizationRequestNotFound", err)
	}
}

func TestPushedAuthorizationRequestRepository_Redis_TTLAlignedToExpiry(t *testing.T) {
	// Arrange
	mr, client := newPARTestServer(t)
	repo := redis.NewPushedAuthorizationRequestRepository(client)
	if err := repo.Save(context.Background(), newPAR("uri-ttl", 5*time.Second)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	mr.FastForward(10 * time.Second)
	_, err := repo.Consume(context.Background(), "uri-ttl")

	// Assert
	if !errors.Is(err, domain.ErrPushedAuthorizationRequestNotFound) {
		t.Errorf("post-TTL Consume err = %v, want ErrPushedAuthorizationRequestNotFound", err)
	}
}
