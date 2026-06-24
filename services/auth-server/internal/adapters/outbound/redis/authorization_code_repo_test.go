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

// newAuthCodeTestServer starts a miniredis server and returns both the server
// (so tests can FastForward) and a connected client.
func newAuthCodeTestServer(t *testing.T) (*miniredis.Miniredis, *goredis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	return mr, client
}

func newAuthCode(raw string, expIn time.Duration) *domain.AuthorizationCode {
	return &domain.AuthorizationCode{
		Code:                raw,
		ClientID:            "client-a",
		Subject:             "user-1",
		RedirectURI:         "https://rp.example.com/cb",
		Scopes:              []string{"openid"},
		CodeChallenge:       "challenge-value",
		CodeChallengeMethod: "S256",
		IssuedAt:            time.Now(),
		ExpiresAt:           time.Now().Add(expIn),
	}
}

func TestAuthorizationCodeRepository_Redis_SaveThenConsume(t *testing.T) {
	// Arrange
	_, client := newAuthCodeTestServer(t)
	repo := redis.NewAuthorizationCodeRepository(client)
	code := newAuthCode("code-a", time.Minute)

	// Act
	if err := repo.Save(context.Background(), code); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := repo.Consume(context.Background(), "code-a")

	// Assert
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.ClientID != "client-a" {
		t.Errorf("ClientID = %q, want %q", got.ClientID, "client-a")
	}
}

func TestAuthorizationCodeRepository_Redis_ConsumeIsAtomic(t *testing.T) {
	// Arrange
	_, client := newAuthCodeTestServer(t)
	repo := redis.NewAuthorizationCodeRepository(client)
	if err := repo.Save(context.Background(), newAuthCode("code-once", time.Minute)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := repo.Consume(context.Background(), "code-once"); err != nil {
		t.Fatalf("first Consume: %v", err)
	}

	// Act
	_, err := repo.Consume(context.Background(), "code-once")

	// Assert
	if !errors.Is(err, domain.ErrAuthorizationCodeNotFound) {
		t.Errorf("second Consume err = %v, want ErrAuthorizationCodeNotFound", err)
	}
}

func TestAuthorizationCodeRepository_Redis_ConsumeUnknown(t *testing.T) {
	// Arrange
	_, client := newAuthCodeTestServer(t)
	repo := redis.NewAuthorizationCodeRepository(client)

	// Act
	_, err := repo.Consume(context.Background(), "never-saved")

	// Assert
	if !errors.Is(err, domain.ErrAuthorizationCodeNotFound) {
		t.Errorf("err = %v, want ErrAuthorizationCodeNotFound", err)
	}
}

func TestAuthorizationCodeRepository_Redis_TTLAlignedToExpiry(t *testing.T) {
	// Arrange — saving with a short TTL and waiting past it must produce
	// NotFound on Consume. Uses miniredis FastForward to avoid wall-clock
	// flakiness.
	mr, client := newAuthCodeTestServer(t)
	repo := redis.NewAuthorizationCodeRepository(client)
	if err := repo.Save(context.Background(), newAuthCode("code-ttl", 5*time.Second)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act — miniredis tracks TTL against a virtual clock that FastForward
	// advances; the real wall clock is irrelevant.
	mr.FastForward(10 * time.Second)
	_, err := repo.Consume(context.Background(), "code-ttl")

	// Assert
	if !errors.Is(err, domain.ErrAuthorizationCodeNotFound) {
		t.Errorf("post-TTL Consume err = %v, want ErrAuthorizationCodeNotFound", err)
	}
}

func TestAuthorizationCodeRepository_Redis_ConcurrentConsumeAtomic(t *testing.T) {
	// Arrange — many concurrent Consume calls; exactly one must succeed.
	// This validates that the Lua script holds the key lock across GET+DEL,
	// rather than allowing interleaving with another client's GET.
	const racers = 32
	_, client := newAuthCodeTestServer(t)
	repo := redis.NewAuthorizationCodeRepository(client)
	if err := repo.Save(context.Background(), newAuthCode("code-race", time.Minute)); err != nil {
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
			if _, err := repo.Consume(context.Background(), "code-race"); err == nil {
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
