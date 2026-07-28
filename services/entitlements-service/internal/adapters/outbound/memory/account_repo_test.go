package memory_test

import (
	"context"
	"sync"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/memory"
)

func TestUpsertPersonalAccount_CreatesOnFirstCall(t *testing.T) {
	// Arrange
	repo := memory.NewAccountRepository()

	// Act
	got, err := repo.UpsertPersonalAccount(context.Background(), "user-1", "u1@example.com")

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil account")
	}
	if got.ID == "" {
		t.Error("expected non-empty ID")
	}
	if got.UserID != "user-1" {
		t.Errorf("UserID = %q, want user-1", got.UserID)
	}
	if got.BillingEmail != "u1@example.com" {
		t.Errorf("BillingEmail = %q, want u1@example.com", got.BillingEmail)
	}
	if !got.IsPersonal() {
		t.Error("expected IsPersonal = true")
	}
}

func TestUpsertPersonalAccount_IsIdempotent(t *testing.T) {
	// Arrange
	repo := memory.NewAccountRepository()

	// Act
	first, err := repo.UpsertPersonalAccount(context.Background(), "user-1", "u1@example.com")
	if err != nil {
		t.Fatalf("first upsert failed: %v", err)
	}
	second, err := repo.UpsertPersonalAccount(context.Background(), "user-1", "u1@example.com")
	if err != nil {
		t.Fatalf("second upsert failed: %v", err)
	}

	// Assert
	if first.ID != second.ID {
		t.Errorf("expected same account ID across upserts, got %q and %q", first.ID, second.ID)
	}
}

func TestUpsertPersonalAccount_DifferentUsersGetDifferentAccounts(t *testing.T) {
	// Arrange
	repo := memory.NewAccountRepository()

	// Act
	a, _ := repo.UpsertPersonalAccount(context.Background(), "user-1", "u1@example.com")
	b, _ := repo.UpsertPersonalAccount(context.Background(), "user-2", "u2@example.com")

	// Assert
	if a.ID == b.ID {
		t.Errorf("expected distinct account IDs, both got %q", a.ID)
	}
}

func TestUpsertPersonalAccount_CreatesOwnerSeat(t *testing.T) {
	// Arrange
	repo := memory.NewAccountRepository()

	// Act
	acc, err := repo.UpsertPersonalAccount(context.Background(), "user-1", "u1@example.com")
	if err != nil {
		t.Fatalf("upsert failed: %v", err)
	}
	seats, err := repo.ListByAccount(context.Background(), acc.ID)
	if err != nil {
		t.Fatalf("list seats failed: %v", err)
	}

	// Assert
	if len(seats) != 1 {
		t.Fatalf("expected exactly 1 seat, got %d", len(seats))
	}
	if seats[0].UserID != "user-1" {
		t.Errorf("seat UserID = %q, want user-1", seats[0].UserID)
	}
	if seats[0].Role != "owner" {
		t.Errorf("seat Role = %q, want owner", seats[0].Role)
	}
}

func TestUpsertPersonalAccount_IdempotentDoesNotDuplicateSeat(t *testing.T) {
	// Arrange
	repo := memory.NewAccountRepository()

	// Act
	acc, _ := repo.UpsertPersonalAccount(context.Background(), "user-1", "u1@example.com")
	_, _ = repo.UpsertPersonalAccount(context.Background(), "user-1", "u1@example.com")
	seats, _ := repo.ListByAccount(context.Background(), acc.ID)

	// Assert
	if len(seats) != 1 {
		t.Errorf("expected 1 seat after two upserts, got %d", len(seats))
	}
}

func TestFindByUserID_ReturnsNotFoundWhenAbsent(t *testing.T) {
	// Arrange
	repo := memory.NewAccountRepository()

	// Act
	_, err := repo.FindByUserID(context.Background(), "no-such-user")

	// Assert
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected not-found error, got %v", err)
	}
}

func TestUpsertPersonalAccount_ConcurrentCallsProduceOneAccount(t *testing.T) {
	// Arrange — a concurrent stampede on the same userID must not
	// duplicate. This is the classic race the partial-unique index
	// protects against in Postgres; the in-memory repo must offer the
	// same guarantee via its own mutex.
	repo := memory.NewAccountRepository()
	const goroutines = 20
	ids := make(chan string, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Act
	for range goroutines {
		go func() {
			defer wg.Done()
			acc, err := repo.UpsertPersonalAccount(context.Background(), "user-race", "u@x.com")
			if err != nil {
				t.Errorf("concurrent upsert failed: %v", err)
				return
			}
			ids <- acc.ID
		}()
	}
	wg.Wait()
	close(ids)

	// Assert
	seen := map[string]struct{}{}
	for id := range ids {
		seen[id] = struct{}{}
	}
	if len(seen) != 1 {
		t.Errorf("expected all concurrent upserts to return the same ID, got %d distinct IDs", len(seen))
	}
}
