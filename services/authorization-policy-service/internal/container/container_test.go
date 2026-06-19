package container_test

import (
	"context"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"
	platform "github.com/jedi-knights/go-platform/container"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/container"
)

func testLogger(t *testing.T) logging.Logger {
	t.Helper()
	return logging.New(logging.Config{Level: "info", Format: "text", Environment: "test"})
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
	ctx := context.Background()
	cfg := minimalConfig()
	c, err := container.New(ctx, cfg, testLogger(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil container")
	}

	handler := platform.MustResolve[*inboundhttp.Handler](ctx, c)
	if handler == nil {
		t.Error("expected non-nil Handler from container")
	}

	gotCfg := platform.MustResolve[*config.Config](ctx, c)
	if gotCfg != cfg {
		t.Error("expected the same Config pointer that was passed to New")
	}
}

// TestNew_Close_DoesNotPanic verifies that Container.Close can be called
// safely on a container wired with in-memory adapters (no real pool or
// Redis client). The platform container also guarantees idempotency on a
// second Close, which we exercise.
func TestNew_Close_DoesNotPanic(t *testing.T) {
	ctx := context.Background()
	c, err := container.New(ctx, minimalConfig(), testLogger(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
