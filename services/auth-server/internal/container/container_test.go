package container_test

import (
	"context"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"
	platform "github.com/jedi-knights/go-platform/container"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/config"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/container"
)

// minimalConfig returns a config with all external URLs empty (in-memory
// fallbacks) and a signing key that passes validation (≥32 chars, not an
// insecure default).
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
	return logging.New(logging.Config{Level: "info", Format: "text", Environment: "test"})
}

func TestNew_NilConfig_ReturnsError(t *testing.T) {
	_, err := container.New(context.Background(), nil, testLogger(t))
	if err == nil {
		t.Fatal("expected error for nil config, got nil")
	}
}

func TestNew_MinimalConfig_ReturnsContainer(t *testing.T) {
	ctx := context.Background()
	cfg := minimalConfig()
	c, err := container.New(ctx, cfg, testLogger(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil container")
	}
	if handler := platform.MustResolve[*inboundhttp.Handler](ctx, c); handler == nil {
		t.Error("expected non-nil Handler resolved from container")
	}
	if gotCfg := platform.MustResolve[*config.Config](ctx, c); gotCfg != cfg {
		t.Error("expected the same Config pointer that was passed to New")
	}
}

func TestNew_DevSeedClients_ReturnsContainer(t *testing.T) {
	ctx := context.Background()
	cfg := minimalConfig()
	cfg.DevSeedClients = true
	cfg.DevClientSecret = "dev-secret"

	c, err := container.New(ctx, cfg, testLogger(t))
	if err != nil {
		t.Fatalf("unexpected error with dev seed clients: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil container")
	}
}
