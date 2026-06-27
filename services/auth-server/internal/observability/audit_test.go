package observability_test

import (
	"context"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/config"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/observability"
)

func testLogger() logging.Logger {
	return logging.New(logging.Config{
		Level:       "info",
		Format:      "json",
		Environment: "test",
	})
}

func TestNewAuditEmitter_StderrOnly(t *testing.T) {
	cfg := &config.Config{
		Audit: config.AuditConfig{}, // no DSN -> stderr only
	}
	w, err := observability.NewAuditEmitter(context.Background(), cfg, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w == nil || w.Emitter == nil {
		t.Fatal("expected non-nil emitter wiring")
	}
	if w.Pool != nil {
		t.Errorf("expected nil pool when DurableDSN is empty, got %v", w.Pool)
	}
}

func TestNewAuditEmitter_NilConfigRejected(t *testing.T) {
	if _, err := observability.NewAuditEmitter(context.Background(), nil, testLogger()); err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestNewAuditEmitter_NilLoggerRejected(t *testing.T) {
	cfg := &config.Config{}
	if _, err := observability.NewAuditEmitter(context.Background(), cfg, nil); err == nil {
		t.Fatal("expected error for nil logger")
	}
}

func TestNewAuditEmitter_BadDSNFailsFast(t *testing.T) {
	cfg := &config.Config{
		Audit: config.AuditConfig{
			DurableDSN: "::: not a valid DSN :::",
		},
	}
	if _, err := observability.NewAuditEmitter(context.Background(), cfg, testLogger()); err == nil {
		t.Fatal("expected error for invalid DSN")
	}
}
