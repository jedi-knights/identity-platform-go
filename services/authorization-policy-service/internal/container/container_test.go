package container_test

import (
	"context"
	"testing"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/container"
)

func testLogger(t *testing.T) logging.Logger {
	t.Helper()
	return logging.NewLogger(logging.Config{Level: "info", Format: "text", Environment: "test"})
}

func minimalConfig() *config.Config {
	return &config.Config{}
}

// TestNew_NilConfig_ReturnsError characterises the nil-guard at the top of New.
func TestNew_NilConfig_ReturnsError(t *testing.T) {
	_, err := container.New(context.Background(), nil, testLogger(t))
	if err == nil {
		t.Fatal("expected error for nil config, got nil")
	}
}

// TestNew_NilLogger_ReturnsError characterises the nil-guard for the logger.
func TestNew_NilLogger_ReturnsError(t *testing.T) {
	_, err := container.New(context.Background(), minimalConfig(), nil)
	if err == nil {
		t.Fatal("expected error for nil logger, got nil")
	}
}

// TestNew_MinimalConfig_ReturnsContainer characterises the happy-path with
// no external services configured (all in-memory fallbacks).
func TestNew_MinimalConfig_ReturnsContainer(t *testing.T) {
	cfg := minimalConfig()
	c, err := container.New(context.Background(), cfg, testLogger(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil container")
	}
	if c.Handler == nil {
		t.Error("expected non-nil Handler")
	}
	if c.Config != cfg {
		t.Error("expected Config to be the same pointer passed to New")
	}
}

// TestNew_Close_DoesNotPanic verifies that Container.Close can be called safely
// on a container wired with in-memory adapters (no real pool or Redis client).
func TestNew_Close_DoesNotPanic(t *testing.T) {
	c, err := container.New(context.Background(), minimalConfig(), testLogger(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c.Close() // must not panic
}
