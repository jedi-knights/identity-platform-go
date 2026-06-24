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

func newTestCode(raw string, expIn time.Duration) *domain.AuthorizationCode {
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

func TestAuthorizationCodeRepository_SaveThenConsume(t *testing.T) {
	// Arrange
	repo := memory.NewAuthorizationCodeRepository()
	code := newTestCode("code-abc", time.Minute)

	// Act
	if err := repo.Save(context.Background(), code); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := repo.Consume(context.Background(), "code-abc")

	// Assert
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.ClientID != "client-a" {
		t.Errorf("ClientID = %q, want %q", got.ClientID, "client-a")
	}
}

func TestAuthorizationCodeRepository_ConsumeIsAtomicReadAndDelete(t *testing.T) {
	// Arrange — second Consume after a successful one must return NotFound.
	// This is the load-bearing invariant the replay-detection cascade depends on.
	repo := memory.NewAuthorizationCodeRepository()
	if err := repo.Save(context.Background(), newTestCode("code-once", time.Minute)); err != nil {
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

func TestAuthorizationCodeRepository_ConsumeUnknownCode(t *testing.T) {
	// Arrange
	repo := memory.NewAuthorizationCodeRepository()

	// Act
	_, err := repo.Consume(context.Background(), "never-saved")

	// Assert
	if !errors.Is(err, domain.ErrAuthorizationCodeNotFound) {
		t.Errorf("err = %v, want ErrAuthorizationCodeNotFound", err)
	}
}

func TestAuthorizationCodeRepository_ConsumeExpiredCode(t *testing.T) {
	// Arrange — already-expired code: Consume must report NotFound, not return it.
	repo := memory.NewAuthorizationCodeRepository()
	if err := repo.Save(context.Background(), newTestCode("code-expired", -time.Second)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	_, err := repo.Consume(context.Background(), "code-expired")

	// Assert
	if !errors.Is(err, domain.ErrAuthorizationCodeNotFound) {
		t.Errorf("err = %v, want ErrAuthorizationCodeNotFound for expired code", err)
	}
}

func TestAuthorizationCodeRepository_ConcurrentConsumeOnlyOneSucceeds(t *testing.T) {
	// Arrange — N goroutines race to Consume the same code; exactly one must
	// receive the code, the rest must receive ErrAuthorizationCodeNotFound.
	const racers = 32
	repo := memory.NewAuthorizationCodeRepository()
	if err := repo.Save(context.Background(), newTestCode("code-race", time.Minute)); err != nil {
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
		t.Errorf("got %d successful Consume calls, want exactly 1", got)
	}
}

func TestAuthorizationCodeRepository_SaveOverwrites(t *testing.T) {
	// Arrange — re-Save under the same code key replaces the prior record.
	// This is documented behavior; tests pin it so an accidental "fail on
	// duplicate" doesn't sneak in.
	repo := memory.NewAuthorizationCodeRepository()
	first := newTestCode("code-dup", time.Minute)
	first.Subject = "user-original"
	second := newTestCode("code-dup", time.Minute)
	second.Subject = "user-replaced"

	if err := repo.Save(context.Background(), first); err != nil {
		t.Fatalf("first Save: %v", err)
	}

	// Act
	if err := repo.Save(context.Background(), second); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	got, err := repo.Consume(context.Background(), "code-dup")

	// Assert
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.Subject != "user-replaced" {
		t.Errorf("Subject = %q, want %q (Save did not overwrite)", got.Subject, "user-replaced")
	}
}
