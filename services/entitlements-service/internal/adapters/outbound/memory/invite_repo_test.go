package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

func TestInsertInvite_AssignsID(t *testing.T) {
	// Arrange
	repo := memory.NewInviteRepository()

	// Act
	got, err := repo.Insert(context.Background(), domain.Invite{
		AccountID:       "acc-1",
		InvitedBySeatID: "seat-1",
		InvitedEmail:    "a@x.com",
		TokenHash:       "hash1",
		ExpiresAt:       time.Now().Add(7 * 24 * time.Hour),
	})

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID == "" {
		t.Error("expected non-empty ID")
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected CreatedAt set")
	}
}

func TestInsertInvite_RejectsDuplicateOpenSameAccountAndEmail(t *testing.T) {
	// Arrange
	repo := memory.NewInviteRepository()
	base := domain.Invite{
		AccountID:       "acc-1",
		InvitedBySeatID: "seat-1",
		InvitedEmail:    "a@x.com",
		ExpiresAt:       time.Now().Add(7 * 24 * time.Hour),
	}
	base.TokenHash = "hash1"
	if _, err := repo.Insert(context.Background(), base); err != nil {
		t.Fatalf("first insert failed: %v", err)
	}

	// Act — same account, same email, still open -> conflict
	base.TokenHash = "hash2"
	_, err := repo.Insert(context.Background(), base)

	// Assert
	if err == nil {
		t.Fatal("expected duplicate-open error, got nil")
	}
}

func TestInsertInvite_AllowsSameEmailOnDifferentAccount(t *testing.T) {
	// Arrange
	repo := memory.NewInviteRepository()
	if _, err := repo.Insert(context.Background(), domain.Invite{
		AccountID: "acc-1", InvitedBySeatID: "seat-1", InvitedEmail: "a@x.com",
		TokenHash: "h1", ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("first: %v", err)
	}

	// Act
	_, err := repo.Insert(context.Background(), domain.Invite{
		AccountID: "acc-2", InvitedBySeatID: "seat-2", InvitedEmail: "a@x.com",
		TokenHash: "h2", ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	})

	// Assert
	if err != nil {
		t.Errorf("expected success for same email on different account, got %v", err)
	}
}

func TestCountOpen_ReturnsZeroForUnknownAccount(t *testing.T) {
	// Arrange
	repo := memory.NewInviteRepository()

	// Act
	n, err := repo.CountOpen(context.Background(), "no-such")

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("count = %d, want 0", n)
	}
}

func TestCountOpen_CountsPendingOnly(t *testing.T) {
	// Arrange — three invites on the same account:
	//   1 pending, 1 accepted, 1 revoked. CountOpen should return 1.
	repo := memory.NewInviteRepository()
	now := time.Now()
	future := now.Add(7 * 24 * time.Hour)

	if _, err := repo.Insert(context.Background(), domain.Invite{
		AccountID: "acc-1", InvitedBySeatID: "s", InvitedEmail: "pending@x.com",
		TokenHash: "h1", ExpiresAt: future,
	}); err != nil {
		t.Fatalf("insert pending: %v", err)
	}
	acceptedTime := now
	if _, err := repo.Insert(context.Background(), domain.Invite{
		AccountID: "acc-1", InvitedBySeatID: "s", InvitedEmail: "accepted@x.com",
		TokenHash: "h2", ExpiresAt: future, AcceptedAt: &acceptedTime,
	}); err != nil {
		t.Fatalf("insert accepted: %v", err)
	}
	revokedTime := now
	if _, err := repo.Insert(context.Background(), domain.Invite{
		AccountID: "acc-1", InvitedBySeatID: "s", InvitedEmail: "revoked@x.com",
		TokenHash: "h3", ExpiresAt: future, RevokedAt: &revokedTime,
	}); err != nil {
		t.Fatalf("insert revoked: %v", err)
	}

	// Act
	n, err := repo.CountOpen(context.Background(), "acc-1")

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Errorf("count = %d, want 1", n)
	}
}

func TestCountOpen_TreatsExpiredAsClosed(t *testing.T) {
	// Arrange
	repo := memory.NewInviteRepository()
	past := time.Now().Add(-24 * time.Hour)
	if _, err := repo.Insert(context.Background(), domain.Invite{
		AccountID: "acc-1", InvitedBySeatID: "s", InvitedEmail: "old@x.com",
		TokenHash: "h1", ExpiresAt: past,
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Act
	n, err := repo.CountOpen(context.Background(), "acc-1")

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("count = %d, want 0 (expired invites are not open)", n)
	}
}
