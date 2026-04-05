package application_test

import (
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/application"
)

func TestNewBCryptHasher_BelowMinCost_FallsBackToDefault(t *testing.T) {
	// cost=0 is below bcrypt.MinCost; the constructor should guard against it
	// so Hash does not fail with InvalidCostError.
	h := application.NewBCryptHasher(0)
	hash, err := h.Hash("password")
	if err != nil {
		t.Fatalf("Hash with cost=0 failed (expected fallback to DefaultCost): %v", err)
	}
	if err := h.Compare(hash, "password"); err != nil {
		t.Errorf("Compare: %v", err)
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if cost < bcrypt.MinCost {
		t.Errorf("hash cost %d is below MinCost %d", cost, bcrypt.MinCost)
	}
}

// TestBCryptHasher_HashAndCompare verifies the round-trip: a hashed password
// must compare successfully, and a wrong password must not.
func TestBCryptHasher_HashAndCompare(t *testing.T) {
	h := application.NewBCryptHasher(bcrypt.MinCost) // MinCost for test speed
	hash, err := h.Hash("correct-horse")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := h.Compare(hash, "correct-horse"); err != nil {
		t.Errorf("Compare with correct password: %v", err)
	}
	if err := h.Compare(hash, "wrong-password"); err == nil {
		t.Error("Compare with wrong password: expected error, got nil")
	}
}
