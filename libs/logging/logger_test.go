//go:build unit

package logging_test

import (
	"context"
	"testing"

	"github.com/ocrosby/identity-platform-go/libs/logging"
)

func TestNewLogger_JSON(t *testing.T) {
	cfg := logging.Config{
		Level:       "debug",
		Format:      "json",
		ServiceName: "test-service",
		Environment: "test",
	}
	l := logging.NewLogger(cfg)
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
	l.Debug("debug message", "key", "value")
	l.Info("info message")
	l.Warn("warn message")
	l.Error("error message")
}

func TestNewLogger_Text(t *testing.T) {
	cfg := logging.Config{
		Level:  "info",
		Format: "text",
	}
	l := logging.NewLogger(cfg)
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
	l.Info("info message")
}

func TestLogger_With(t *testing.T) {
	l := logging.NewLogger(logging.Config{Level: "debug", Format: "text"})
	l2 := l.With("request_id", "abc123")
	if l2 == nil {
		t.Fatal("expected non-nil logger from With")
	}
	l2.Info("with extra field")
}

func TestWithTraceID(t *testing.T) {
	ctx := context.Background()
	ctx = logging.WithTraceID(ctx, "trace-xyz")
	got := logging.TraceIDFromContext(ctx)
	if got != "trace-xyz" {
		t.Fatalf("expected trace-xyz, got %s", got)
	}
}

func TestTraceIDFromContext_Missing(t *testing.T) {
	ctx := context.Background()
	got := logging.TraceIDFromContext(ctx)
	if got != "" {
		t.Fatalf("expected empty string, got %s", got)
	}
}

func TestWithContext_FromContext(t *testing.T) {
	l := logging.NewLogger(logging.Config{Level: "info", Format: "text"})
	ctx := logging.WithContext(context.Background(), l)
	got := logging.FromContext(ctx)
	if got == nil {
		t.Fatal("expected non-nil logger from context")
	}
}

func TestFromContext_Default(t *testing.T) {
	ctx := context.Background()
	got := logging.FromContext(ctx)
	if got == nil {
		t.Fatal("expected default logger, got nil")
	}
}

func TestWithTraceFromContext(t *testing.T) {
	l := logging.NewLogger(logging.Config{Level: "debug", Format: "text"})
	ctx := logging.WithTraceID(context.Background(), "trace-abc")
	enriched := logging.WithTraceFromContext(ctx, l)
	if enriched == nil {
		t.Fatal("expected non-nil enriched logger")
	}
	enriched.Info("message with trace")
}

func TestWithTraceFromContext_NoTrace(t *testing.T) {
	l := logging.NewLogger(logging.Config{Level: "debug", Format: "text"})
	ctx := context.Background()
	same := logging.WithTraceFromContext(ctx, l)
	if same == nil {
		t.Fatal("expected non-nil logger when no trace ID")
	}
}
