//go:build integration

package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/postgres"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

// setupInvites brings up a fresh Postgres, runs migrations, truncates
// dependents, seeds an account + owner seat, and returns both repos
// wired against the same pool.
func setupInvites(t *testing.T) (*postgres.AccountRepository, *postgres.InviteRepository, string, string, func()) {
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
	if _, err := pool.Exec(context.Background(), "TRUNCATE accounts CASCADE"); err != nil {
		pool.Close()
		t.Fatalf("truncate: %v", err)
	}
	accts := postgres.NewAccountRepository(pool)
	acc, err := accts.UpsertPersonalAccount(context.Background(), "owner-user", "o@example.com")
	if err != nil {
		pool.Close()
		t.Fatalf("seed account: %v", err)
	}
	seats, err := accts.ListByAccount(context.Background(), acc.ID)
	if err != nil || len(seats) == 0 {
		pool.Close()
		t.Fatalf("seed seats: %v %d", err, len(seats))
	}
	return accts, postgres.NewInviteRepository(pool), acc.ID, seats[0].ID, func() { pool.Close() }
}

func TestInviteInsert_PersistsAndReturnsRow(t *testing.T) {
	_, invRepo, accountID, ownerSeatID, cleanup := setupInvites(t)
	defer cleanup()

	inv, err := invRepo.Insert(context.Background(), domain.Invite{
		AccountID:       accountID,
		InvitedBySeatID: ownerSeatID,
		InvitedEmail:    "a@x.com",
		TokenHash:       "hash-a",
		ExpiresAt:       time.Now().Add(7 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if inv.ID == "" {
		t.Error("expected non-empty ID")
	}
	if inv.CreatedAt.IsZero() {
		t.Error("expected CreatedAt populated")
	}
	n, err := invRepo.CountOpen(context.Background(), accountID)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("open count = %d, want 1", n)
	}
}

func TestInviteInsert_DuplicateOpenReturnsConflict(t *testing.T) {
	_, invRepo, accountID, ownerSeatID, cleanup := setupInvites(t)
	defer cleanup()

	base := domain.Invite{
		AccountID:       accountID,
		InvitedBySeatID: ownerSeatID,
		InvitedEmail:    "dup@x.com",
		ExpiresAt:       time.Now().Add(7 * 24 * time.Hour),
	}
	base.TokenHash = "hash-1"
	if _, err := invRepo.Insert(context.Background(), base); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	base.TokenHash = "hash-2"
	_, err := invRepo.Insert(context.Background(), base)
	if err == nil {
		t.Fatal("expected conflict, got nil")
	}
	if !apperrors.IsConflict(err) {
		t.Errorf("expected conflict, got %v", err)
	}
}

func TestInviteCountOpen_TreatsExpiredAsClosed(t *testing.T) {
	_, invRepo, accountID, ownerSeatID, cleanup := setupInvites(t)
	defer cleanup()

	if _, err := invRepo.Insert(context.Background(), domain.Invite{
		AccountID:       accountID,
		InvitedBySeatID: ownerSeatID,
		InvitedEmail:    "old@x.com",
		TokenHash:       "hash-old",
		ExpiresAt:       time.Now().Add(-24 * time.Hour),
	}); err != nil {
		t.Fatalf("insert expired: %v", err)
	}
	n, err := invRepo.CountOpen(context.Background(), accountID)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("open count = %d, want 0 (expired invite shouldn't count)", n)
	}
}

func TestSeatAllowance_DefaultsToOneWithNoPlan(t *testing.T) {
	acctRepo, _, accountID, _, cleanup := setupInvites(t)
	defer cleanup()

	n, err := acctRepo.SeatAllowance(context.Background(), accountID)
	if err != nil {
		t.Fatalf("SeatAllowance: %v", err)
	}
	if n != 1 {
		t.Errorf("SeatAllowance = %d, want 1 (personal-account default with no active plan)", n)
	}
}
