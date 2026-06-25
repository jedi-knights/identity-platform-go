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

func newTestChallenge(id string, expIn time.Duration) *domain.LoginChallenge {
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

func TestLoginChallengeRepository_SaveThenConsume(t *testing.T) {
	// Arrange
	repo := memory.NewLoginChallengeRepository()
	c := newTestChallenge("ch-abc", time.Minute)

	// Act
	if err := repo.Save(context.Background(), c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := repo.Consume(context.Background(), "ch-abc")

	// Assert
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.ClientID != "client-a" {
		t.Errorf("ClientID = %q, want %q", got.ClientID, "client-a")
	}
}

func TestLoginChallengeRepository_SaveThenGetDoesNotRemove(t *testing.T) {
	// Arrange — Get is the read-only path used by login-ui to render the
	// sign-in screen; the record must remain for a later Consume.
	repo := memory.NewLoginChallengeRepository()
	if err := repo.Save(context.Background(), newTestChallenge("ch-get", time.Minute)); err != nil {
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

func TestLoginChallengeRepository_GetUnknown(t *testing.T) {
	// Arrange
	repo := memory.NewLoginChallengeRepository()

	// Act
	_, err := repo.Get(context.Background(), "never-saved")

	// Assert
	if !errors.Is(err, domain.ErrLoginChallengeNotFound) {
		t.Errorf("err = %v, want ErrLoginChallengeNotFound", err)
	}
}

func TestLoginChallengeRepository_ConsumeIsAtomicReadAndDelete(t *testing.T) {
	// Arrange — second Consume after a successful one must return NotFound.
	repo := memory.NewLoginChallengeRepository()
	if err := repo.Save(context.Background(), newTestChallenge("ch-once", time.Minute)); err != nil {
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

func TestLoginChallengeRepository_ConsumeUnknown(t *testing.T) {
	// Arrange
	repo := memory.NewLoginChallengeRepository()

	// Act
	_, err := repo.Consume(context.Background(), "never-saved")

	// Assert
	if !errors.Is(err, domain.ErrLoginChallengeNotFound) {
		t.Errorf("err = %v, want ErrLoginChallengeNotFound", err)
	}
}

func TestLoginChallengeRepository_ConsumeExpired(t *testing.T) {
	// Arrange — already-expired challenge: Consume must report NotFound.
	repo := memory.NewLoginChallengeRepository()
	if err := repo.Save(context.Background(), newTestChallenge("ch-expired", -time.Second)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	_, err := repo.Consume(context.Background(), "ch-expired")

	// Assert
	if !errors.Is(err, domain.ErrLoginChallengeNotFound) {
		t.Errorf("err = %v, want ErrLoginChallengeNotFound for expired challenge", err)
	}
}

func TestLoginChallengeRepository_GetExpiredDropsAndReportsNotFound(t *testing.T) {
	// Arrange — Get on an expired entry both reports NotFound and removes
	// the record so the store cannot grow unbounded under heavy authorize
	// traffic. We verify the removal by hitting Consume afterward.
	repo := memory.NewLoginChallengeRepository()
	if err := repo.Save(context.Background(), newTestChallenge("ch-stale", -time.Second)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	_, getErr := repo.Get(context.Background(), "ch-stale")
	_, consumeErr := repo.Consume(context.Background(), "ch-stale")

	// Assert
	if !errors.Is(getErr, domain.ErrLoginChallengeNotFound) {
		t.Errorf("Get err = %v, want ErrLoginChallengeNotFound", getErr)
	}
	if !errors.Is(consumeErr, domain.ErrLoginChallengeNotFound) {
		t.Errorf("post-Get Consume err = %v, want ErrLoginChallengeNotFound (Get must drop expired)", consumeErr)
	}
}

func TestLoginChallengeRepository_UpdateExistingID(t *testing.T) {
	// Arrange — Update is the path the consent flow uses to add SessionID /
	// ConsentGranted onto an in-flight challenge before redemption.
	repo := memory.NewLoginChallengeRepository()
	original := newTestChallenge("ch-upd", time.Minute)
	if err := repo.Save(context.Background(), original); err != nil {
		t.Fatalf("Save: %v", err)
	}
	updated := newTestChallenge("ch-upd", time.Minute)
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

func TestLoginChallengeRepository_UpdateUnknownID(t *testing.T) {
	// Arrange — Update must not create a new record; it is for in-flight
	// state only. An unknown ID is an indication of a stale or hijacked
	// redirect and must surface as ErrLoginChallengeNotFound.
	repo := memory.NewLoginChallengeRepository()

	// Act
	err := repo.Update(context.Background(), newTestChallenge("ch-ghost", time.Minute))

	// Assert
	if !errors.Is(err, domain.ErrLoginChallengeNotFound) {
		t.Errorf("err = %v, want ErrLoginChallengeNotFound", err)
	}
}

func TestLoginChallengeRepository_ConcurrentConsumeOnlyOneSucceeds(t *testing.T) {
	// Arrange — N goroutines race to Consume the same challenge; exactly
	// one must succeed. This is the same invariant as authorization_code
	// Consume and is what prevents two concurrent /internal/issue-code calls
	// from both redeeming the same challenge.
	const racers = 32
	repo := memory.NewLoginChallengeRepository()
	if err := repo.Save(context.Background(), newTestChallenge("ch-race", time.Minute)); err != nil {
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
		t.Errorf("got %d successful Consume calls, want exactly 1", got)
	}
}

func TestLoginChallengeRepository_SaveOverwrites(t *testing.T) {
	// Arrange — documented behavior: Save under an existing ID overwrites.
	// This matches Redis SET semantics and avoids forcing the caller to
	// delete-then-save.
	repo := memory.NewLoginChallengeRepository()
	first := newTestChallenge("ch-dup", time.Minute)
	first.State = "state-original"
	second := newTestChallenge("ch-dup", time.Minute)
	second.State = "state-replaced"

	if err := repo.Save(context.Background(), first); err != nil {
		t.Fatalf("first Save: %v", err)
	}

	// Act
	if err := repo.Save(context.Background(), second); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	got, err := repo.Consume(context.Background(), "ch-dup")

	// Assert
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.State != "state-replaced" {
		t.Errorf("State = %q, want %q (Save did not overwrite)", got.State, "state-replaced")
	}
}
