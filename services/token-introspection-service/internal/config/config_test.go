package config_test

import (
	"testing"

	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/config"
)

// TestLoad_RequiresIntrospectionSecret verifies that the service refuses to start
// when no caller-authentication secret is configured (RFC 7662 §2.1 MUST).
func TestLoad_RequiresIntrospectionSecret(t *testing.T) {
	// Arrange — valid signing key, empty introspection secret.
	t.Setenv("INTROSPECT_JWT_SIGNING_KEY", "a-valid-32-char-signing-key-here!!")
	t.Setenv("INTROSPECT_INTROSPECTION_SECRET", "")

	// Act
	_, err := config.Load()

	// Assert
	if err == nil {
		t.Fatal("expected error when INTROSPECT_INTROSPECTION_SECRET is empty, got nil")
	}
}

// TestLoad_AcceptsNonEmptySecret verifies that a configured secret is read correctly.
func TestLoad_AcceptsNonEmptySecret(t *testing.T) {
	// Arrange
	t.Setenv("INTROSPECT_JWT_SIGNING_KEY", "a-valid-32-char-signing-key-here!!")
	t.Setenv("INTROSPECT_INTROSPECTION_SECRET", "some-pre-shared-secret")

	// Act
	cfg, err := config.Load()

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Introspection.Secret != "some-pre-shared-secret" {
		t.Errorf("Secret = %q, want %q", cfg.Introspection.Secret, "some-pre-shared-secret")
	}
}
