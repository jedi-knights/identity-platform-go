//go:build integration

package postgres_test

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/postgres"
)

// The integration tests below require a running Postgres reachable via
// ENTITLEMENTS_POSTGRES_TEST_URL. They are gated behind the
// `integration` build tag so a bare `go test ./...` skips them.
//
// Locally:
//   docker run --rm -d --name ent-it-pg -e POSTGRES_PASSWORD=x \
//     -e POSTGRES_DB=ent -p 55440:5432 postgres:16
//   ENTITLEMENTS_POSTGRES_TEST_URL=postgres://postgres:x@localhost:55440/ent?sslmode=disable \
//     go test -tags integration ./internal/adapters/outbound/postgres/...

func setup(t *testing.T) (*postgres.AccountRepository, func()) {
	t.Helper()
	url := os.Getenv("ENTITLEMENTS_POSTGRES_TEST_URL")
	if url == "" {
		t.Skip("ENTITLEMENTS_POSTGRES_TEST_URL not set")
	}
	if err := postgres.RunMigrations(url); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	pool, err := postgres.Connect(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// Truncate to a clean state — CASCADE clears dependent seat rows.
	if _, err := pool.Exec(context.Background(), "TRUNCATE accounts CASCADE"); err != nil {
		pool.Close()
		t.Fatalf("truncate: %v", err)
	}
	return postgres.NewAccountRepository(pool), func() { pool.Close() }
}

func TestUpsertPersonalAccount_CreatesAndSeatsOwner(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()

	acc, err := repo.UpsertPersonalAccount(context.Background(), "user-1", "u1@example.com")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if acc.ID == "" || acc.UserID != "user-1" || acc.BillingEmail != "u1@example.com" {
		t.Errorf("bad account shape: %+v", acc)
	}
	seats, err := repo.ListByAccount(context.Background(), acc.ID)
	if err != nil {
		t.Fatalf("list seats: %v", err)
	}
	if len(seats) != 1 {
		t.Fatalf("expected 1 seat, got %d", len(seats))
	}
	if seats[0].UserID != "user-1" || string(seats[0].Role) != "owner" {
		t.Errorf("bad seat shape: %+v", seats[0])
	}
}

func TestUpsertPersonalAccount_IsIdempotent(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()

	first, _ := repo.UpsertPersonalAccount(context.Background(), "user-1", "u1@example.com")
	second, _ := repo.UpsertPersonalAccount(context.Background(), "user-1", "u1@example.com")
	if first.ID != second.ID {
		t.Errorf("expected same account across upserts, got %q and %q", first.ID, second.ID)
	}
	seats, _ := repo.ListByAccount(context.Background(), first.ID)
	if len(seats) != 1 {
		t.Errorf("expected 1 seat after two upserts, got %d", len(seats))
	}
}

func TestUpsertPersonalAccount_ConcurrentStampede(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()

	const goroutines = 15
	ids := make(chan string, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			acc, err := repo.UpsertPersonalAccount(context.Background(), "user-race", "u@x.com")
			if err != nil {
				t.Errorf("concurrent upsert: %v", err)
				return
			}
			ids <- acc.ID
		}()
	}
	wg.Wait()
	close(ids)
	seen := map[string]struct{}{}
	for id := range ids {
		seen[id] = struct{}{}
	}
	if len(seen) != 1 {
		t.Errorf("expected all concurrent upserts to return the same ID, got %d distinct", len(seen))
	}
}

func TestFindByUserID_NotFound(t *testing.T) {
	repo, cleanup := setup(t)
	defer cleanup()

	_, err := repo.FindByUserID(context.Background(), "no-such-user")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected not-found error, got %v", err)
	}
}
