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

// newChallengeTestServer starts a miniredis server and returns both the
// server (so tests can FastForward) and a connected client.
func newChallengeTestServer(t *testing.T) (*miniredis.Miniredis, *goredis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	return mr, client
}

func newChallenge(id string, expIn time.Duration) *domain.LoginChallenge {
	return &domain.LoginChallenge{
		ID:                  id,
		ClientID:            "client-a",
		RedirectURI:         "https://rp.example.com/cb",
		Scopes:              []string{"openid"},
		State:               "state-value",
		Nonce:               "nonce-value",
		CodeChallenge:       "challenge-value",
		CodeChallengeMethod: "S256",
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(expIn),
	}
}

func TestLoginChallengeRepository_Redis_SaveThenConsume(t *testing.T) {
	// Arrange
	_, client := newChallengeTestServer(t)
	repo := redis.NewLoginChallengeRepository(client)
	c := newChallenge("ch-a", time.Minute)

	// Act
	if err := repo.Save(context.Background(), c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := repo.Consume(context.Background(), "ch-a")

	// Assert
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.ClientID != "client-a" {
		t.Errorf("ClientID = %q, want %q", got.ClientID, "client-a")
	}
}

func TestLoginChallengeRepository_Redis_GetDoesNotRemove(t *testing.T) {
	// Arrange
	_, client := newChallengeTestServer(t)
	repo := redis.NewLoginChallengeRepository(client)
	if err := repo.Save(context.Background(), newChallenge("ch-get", time.Minute)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	first, errFirst := repo.Get(context.Background(), "ch-get")
	second, errSecond := repo.Get(context.Background(), "ch-get")

	// Assert
	if errFirst != nil || errSecond != nil {
		t.Fatalf("Get errors: first=%v second=%v", errFirst, errSecond)
	}
	if first == nil || second == nil {
		t.Fatal("Get returned nil challenge")
	}
}

func TestLoginChallengeRepository_Redis_GetUnknown(t *testing.T) {
	// Arrange
	_, client := newChallengeTestServer(t)
	repo := redis.NewLoginChallengeRepository(client)

	// Act
	_, err := repo.Get(context.Background(), "never-saved")

	// Assert
	if !errors.Is(err, domain.ErrLoginChallengeNotFound) {
		t.Errorf("err = %v, want ErrLoginChallengeNotFound", err)
	}
}

func TestLoginChallengeRepository_Redis_ConsumeIsAtomic(t *testing.T) {
	// Arrange
	_, client := newChallengeTestServer(t)
	repo := redis.NewLoginChallengeRepository(client)
	if err := repo.Save(context.Background(), newChallenge("ch-once", time.Minute)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := repo.Consume(context.Background(), "ch-once"); err != nil {
		t.Fatalf("first Consume: %v", err)
	}

	// Act
	_, err := repo.Consume(context.Background(), "ch-once")

	// Assert
	if !errors.Is(err, domain.ErrLoginChallengeNotFound) {
		t.Errorf("second Consume err = %v, want ErrLoginChallengeNotFound", err)
	}
}

func TestLoginChallengeRepository_Redis_ConsumeUnknown(t *testing.T) {
	// Arrange
	_, client := newChallengeTestServer(t)
	repo := redis.NewLoginChallengeRepository(client)

	// Act
	_, err := repo.Consume(context.Background(), "never-saved")

	// Assert
	if !errors.Is(err, domain.ErrLoginChallengeNotFound) {
		t.Errorf("err = %v, want ErrLoginChallengeNotFound", err)
	}
}

func TestLoginChallengeRepository_Redis_TTLAlignedToExpiry(t *testing.T) {
	// Arrange — saving with a short TTL and FastForwarding past it must
	// produce NotFound on Consume.
	mr, client := newChallengeTestServer(t)
	repo := redis.NewLoginChallengeRepository(client)
	if err := repo.Save(context.Background(), newChallenge("ch-ttl", 5*time.Second)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	mr.FastForward(10 * time.Second)
	_, err := repo.Consume(context.Background(), "ch-ttl")

	// Assert
	if !errors.Is(err, domain.ErrLoginChallengeNotFound) {
		t.Errorf("post-TTL Consume err = %v, want ErrLoginChallengeNotFound", err)
	}
}

func TestLoginChallengeRepository_Redis_SaveDropsExpired(t *testing.T) {
	// Arrange — passing an already-expired challenge to Save is a no-op:
	// the TTL guard in the adapter prevents the key from being written at
	// all (Redis rejects a 0/negative TTL on SET).
	_, client := newChallengeTestServer(t)
	repo := redis.NewLoginChallengeRepository(client)

	// Act
	if err := repo.Save(context.Background(), newChallenge("ch-stale", -time.Second)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	_, err := repo.Get(context.Background(), "ch-stale")

	// Assert
	if !errors.Is(err, domain.ErrLoginChallengeNotFound) {
		t.Errorf("Get err = %v, want ErrLoginChallengeNotFound (Save must not persist expired challenges)", err)
	}
}

func TestLoginChallengeRepository_Redis_UpdateExistingID(t *testing.T) {
	// Arrange — consent flow path: load an in-flight challenge with
	// SessionID and ConsentGranted populated before /internal/issue-code.
	_, client := newChallengeTestServer(t)
	repo := redis.NewLoginChallengeRepository(client)
	if err := repo.Save(context.Background(), newChallenge("ch-upd", time.Minute)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	updated := newChallenge("ch-upd", time.Minute)
	updated.SessionID = "sess-123"
	updated.ConsentGranted = []string{"openid", "profile"}

	// Act
	if err := repo.Update(context.Background(), updated); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := repo.Consume(context.Background(), "ch-upd")

	// Assert
	if err != nil {
		t.Fatalf("Consume after Update: %v", err)
	}
	if got.SessionID != "sess-123" {
		t.Errorf("SessionID = %q, want %q", got.SessionID, "sess-123")
	}
	if len(got.ConsentGranted) != 2 {
		t.Errorf("ConsentGranted = %v, want 2 entries", got.ConsentGranted)
	}
}

func TestLoginChallengeRepository_Redis_UpdateUnknownID(t *testing.T) {
	// Arrange — Update uses SET XX, which must fail when the key is absent.
	// Surfaces as ErrLoginChallengeNotFound so callers do not import goredis.
	_, client := newChallengeTestServer(t)
	repo := redis.NewLoginChallengeRepository(client)

	// Act
	err := repo.Update(context.Background(), newChallenge("ch-ghost", time.Minute))

	// Assert
	if !errors.Is(err, domain.ErrLoginChallengeNotFound) {
		t.Errorf("err = %v, want ErrLoginChallengeNotFound", err)
	}
}

func TestLoginChallengeRepository_Redis_ConcurrentConsumeAtomic(t *testing.T) {
	// Arrange — many concurrent Consume calls; exactly one must succeed.
	// Validates that the Lua script holds the key across GET+DEL, not that
	// two clients can both GET before either DELs.
	const racers = 32
	_, client := newChallengeTestServer(t)
	repo := redis.NewLoginChallengeRepository(client)
	if err := repo.Save(context.Background(), newChallenge("ch-race", time.Minute)); err != nil {
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
			if _, err := repo.Consume(context.Background(), "ch-race"); err == nil {
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
