package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func TestDPoPProofRepository_MarkUsed_FirstUseSucceeds(t *testing.T) {
	// Arrange
	repo := memory.NewDPoPProofRepository()

	// Act
	err := repo.MarkUsed(context.Background(), "jti-1", time.Now().Add(time.Minute))

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDPoPProofRepository_MarkUsed_ReplayWithinWindowFails(t *testing.T) {
	// Arrange
	repo := memory.NewDPoPProofRepository()
	expiresAt := time.Now().Add(time.Minute)
	if err := repo.MarkUsed(context.Background(), "jti-1", expiresAt); err != nil {
		t.Fatalf("unexpected error on first use: %v", err)
	}

	// Act
	err := repo.MarkUsed(context.Background(), "jti-1", expiresAt)

	// Assert
	if !errors.Is(err, domain.ErrDPoPProofReplayed) {
		t.Errorf("expected ErrDPoPProofReplayed, got: %v", err)
	}
}

func TestDPoPProofRepository_MarkUsed_ReplayAfterExpirySucceeds(t *testing.T) {
	// Arrange
	repo := memory.NewDPoPProofRepository()
	expiresAt := time.Now().Add(-time.Second) // already expired
	if err := repo.MarkUsed(context.Background(), "jti-1", expiresAt); err != nil {
		t.Fatalf("unexpected error on first use: %v", err)
	}

	// Act
	err := repo.MarkUsed(context.Background(), "jti-1", time.Now().Add(time.Minute))

	// Assert
	if err != nil {
		t.Errorf("expected reuse of an expired jti to succeed, got: %v", err)
	}
}

func TestDPoPProofRepository_MarkUsed_DistinctJTIsDoNotCollide(t *testing.T) {
	// Arrange
	repo := memory.NewDPoPProofRepository()
	expiresAt := time.Now().Add(time.Minute)
	if err := repo.MarkUsed(context.Background(), "jti-1", expiresAt); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Act
	err := repo.MarkUsed(context.Background(), "jti-2", expiresAt)

	// Assert
	if err != nil {
		t.Errorf("expected a distinct jti to succeed, got: %v", err)
	}
}
