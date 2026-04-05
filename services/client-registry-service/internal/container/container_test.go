package container_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/container"
)

func testLogger(t *testing.T) logging.Logger {
	t.Helper()
	return logging.NewLogger(logging.Config{Level: "error", Format: "text", Environment: "test"})
}

func TestNew_NilConfig_ReturnsError(t *testing.T) {
	_, err := container.New(context.Background(), nil, testLogger(t))
	if err == nil {
		t.Fatal("expected error for nil config, got nil")
	}
}

func TestNew_NilLogger_ReturnsError(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Host: "localhost", Port: 8082},
	}
	_, err := container.New(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error for nil logger, got nil")
	}
}

func TestNew_MinimalConfig_ReturnsContainer(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Host: "localhost", Port: 8082},
		Log:    config.LogConfig{Level: "error", Format: "text", Environment: "test"},
	}

	ctr, err := container.New(context.Background(), cfg, testLogger(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ctr.Close()

	if ctr.Handler == nil {
		t.Error("expected non-nil Handler")
	}

	// Smoke-test: verify the wired handler responds to /health without panicking.
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	ctr.Handler.Health(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("health smoke-test got status %d, want 200", w.Code)
	}
}

// TestContainer_Close_Idempotent verifies that calling Close twice does not panic.
func TestContainer_Close_Idempotent(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Host: "localhost", Port: 8082},
		Log:    config.LogConfig{Level: "error", Format: "text", Environment: "test"},
	}
	ctr, err := container.New(context.Background(), cfg, testLogger(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctr.Close()
	ctr.Close() // must not panic
}

// TestNew_InvalidDatabaseURL_ReturnsError verifies that an invalid DATABASE_URL
// causes New to return a wrapped error before any attempt to serve traffic.
// A context deadline is set to prevent the test hanging under slow DNS resolution.
func TestNew_InvalidDatabaseURL_ReturnsError(t *testing.T) {
	cfg := &config.Config{
		Database: config.DatabaseConfig{URL: "postgres://invalid-host:5432/nodb?connect_timeout=1"},
		Server:   config.ServerConfig{Host: "localhost", Port: 8082},
		Log:      config.LogConfig{Level: "error", Format: "text", Environment: "test"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := container.New(ctx, cfg, testLogger(t))
	if err == nil {
		t.Fatal("expected error for unreachable postgres URL, got nil")
	}
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}
