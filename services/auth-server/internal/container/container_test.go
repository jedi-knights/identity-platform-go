package container_test

import (
	"testing"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/config"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/container"
)

// minimalConfig returns a config with all external URLs empty (in-memory fallbacks)
// and a signing key that passes validation (≥32 chars, not an insecure default).
func minimalConfig() *config.Config {
	return &config.Config{
		JWT: config.JWTConfig{
			SigningKey: "this-is-a-valid-signing-key-for-tests-only",
			Issuer:     "test-issuer",
		},
		Token: config.TokenConfig{
			TTLSeconds:             300,
			RefreshTokenTTLSeconds: 604800,
		},
	}
}

func testLogger(t *testing.T) logging.Logger {
	t.Helper()
	return logging.NewLogger(logging.Config{Level: "info", Format: "text", Environment: "test"})
}

func TestNew_NilConfig_ReturnsError(t *testing.T) {
	_, err := container.New(nil, testLogger(t))
	if err == nil {
		t.Fatal("expected error for nil config, got nil")
	}
}

func TestNew_MinimalConfig_ReturnsContainer(t *testing.T) {
	cfg := minimalConfig()
	c, err := container.New(cfg, testLogger(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil container")
	}
	if c.Handler == nil {
		t.Error("expected non-nil Handler")
	}
	if c.Logger == nil {
		t.Error("expected non-nil Logger")
	}
	if c.Config != cfg {
		t.Error("expected Config to be the same pointer passed to New")
	}
}

func TestNew_DevSeedClients_ReturnsContainer(t *testing.T) {
	cfg := minimalConfig()
	cfg.DevSeedClients = true
	cfg.DevClientSecret = "dev-secret"

	c, err := container.New(cfg, testLogger(t))
	if err != nil {
		t.Fatalf("unexpected error with dev seed clients: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil container")
	}
}
