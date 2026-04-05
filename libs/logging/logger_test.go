package logging_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/ocrosby/identity-platform-go/libs/logging"
)

// newTestLogger returns a Logger and the buffer it writes to.
// Use the buffer to assert on log output in tests.
func newTestLogger(t *testing.T, format string) (logging.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	l := logging.NewLogger(logging.Config{
		Level:  "debug",
		Format: format,
		Output: &buf,
	})
	return l, &buf
}

func TestNewLogger_JSON_WritesOutput(t *testing.T) {
	var buf bytes.Buffer
	l := logging.NewLogger(logging.Config{
		Level:       "debug",
		Format:      "json",
		ServiceName: "test-svc",
		Environment: "test",
		Output:      &buf,
	})
	l.Info("hello world")

	out := buf.String()
	for _, want := range []string{`"hello world"`, `"service_name":"test-svc"`, `"environment":"test"`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got: %s", want, out)
		}
	}
}

func TestNewLogger_Text(t *testing.T) {
	l, buf := newTestLogger(t, "text")
	l.Info("info message")
	if !strings.Contains(buf.String(), "info message") {
		t.Errorf("expected message in output, got: %s", buf.String())
	}
}

func TestNewLogger_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := logging.NewLogger(logging.Config{Level: "warn", Format: "json", Output: &buf})

	l.Debug("debug suppressed")
	l.Info("info suppressed")
	l.Warn("warn visible")

	out := buf.String()
	if strings.Contains(out, "debug suppressed") {
		t.Error("debug message should be filtered at warn level")
	}
	if strings.Contains(out, "info suppressed") {
		t.Error("info message should be filtered at warn level")
	}
	if !strings.Contains(out, "warn visible") {
		t.Errorf("warn message should appear, got: %s", out)
	}
}

func TestLogger_With(t *testing.T) {
	l, buf := newTestLogger(t, "json")
	l2 := l.With("request_id", "abc123")
	if l2 == nil {
		t.Fatal("expected non-nil logger from With")
	}
	l2.Info("with extra field")
	if !strings.Contains(buf.String(), `"request_id":"abc123"`) {
		t.Errorf("expected request_id field in output, got: %s", buf.String())
	}
}

// TestNewLogger_UnknownLevel_DefaultsToInfo confirms that any unrecognised level
// string causes a warning to be emitted during construction and the logger
// defaults to INFO (suppressing DEBUG messages).
func TestNewLogger_UnknownLevel_DefaultsToInfo(t *testing.T) {
	cases := []string{"verbose", "trace", "fatal", "VERBOSE"}
	for _, level := range cases {
		t.Run(level, func(t *testing.T) {
			var buf bytes.Buffer
			l := logging.NewLogger(logging.Config{
				Level:  level,
				Format: "json",
				Output: &buf,
			})

			// The warning must be emitted during construction.
			if !strings.Contains(buf.String(), "unknown log level") {
				t.Errorf("expected unknown-level warning, got: %s", buf.String())
			}

			// DEBUG must be suppressed at the INFO default.
			buf.Reset()
			l.Debug("should be suppressed")
			if strings.Contains(buf.String(), "should be suppressed") {
				t.Errorf("debug should be suppressed when level defaults to INFO")
			}
		})
	}
}

// TestNewLogger_UppercaseLevel confirms that level strings in common uppercase
// forms (e.g. from environment variables) are accepted without triggering the
// unknown-level warning.
func TestNewLogger_UppercaseLevel(t *testing.T) {
	for _, level := range []string{"DEBUG", "INFO", "WARN", "ERROR", "Info", "Debug"} {
		t.Run(level, func(t *testing.T) {
			var buf bytes.Buffer
			logging.NewLogger(logging.Config{Level: level, Format: "json", Output: &buf})
			if strings.Contains(buf.String(), "unknown log level") {
				t.Errorf("level %q triggered unknown-level warning: %s", level, buf.String())
			}
		})
	}
}

func TestWithTraceID(t *testing.T) {
	ctx := context.Background()
	ctx = logging.WithTraceID(ctx, "trace-xyz")
	if got := logging.TraceIDFromContext(ctx); got != "trace-xyz" {
		t.Fatalf("TraceIDFromContext = %q, want %q", got, "trace-xyz")
	}
}

func TestTraceIDFromContext_Missing(t *testing.T) {
	if got := logging.TraceIDFromContext(context.Background()); got != "" {
		t.Fatalf("TraceIDFromContext on empty context = %q, want empty string", got)
	}
}

func TestWithContext_FromContext(t *testing.T) {
	l, _ := newTestLogger(t, "text")
	ctx := logging.WithContext(context.Background(), l)
	if got := logging.FromContext(ctx); got == nil {
		t.Fatal("FromContext returned nil, want the stored logger")
	}
}

// TestFromContext_Default confirms the fallback returns a non-nil logger.
// Note: the fallback logger writes to os.Stdout, not to a captured buffer.
// Tests that need to assert on log output must inject a logger via WithContext.
func TestFromContext_Default(t *testing.T) {
	if got := logging.FromContext(context.Background()); got == nil {
		t.Fatal("FromContext on empty context returned nil, want a default logger")
	}
}

// TestWithTraceFromContext confirms that the trace_id field appears in log output.
func TestWithTraceFromContext(t *testing.T) {
	l, buf := newTestLogger(t, "json")
	ctx := logging.WithTraceID(context.Background(), "trace-abc")
	enriched := logging.WithTraceFromContext(ctx, l)
	if enriched == nil {
		t.Fatal("WithTraceFromContext returned nil")
	}
	enriched.Info("message with trace")
	if !strings.Contains(buf.String(), `"trace_id":"trace-abc"`) {
		t.Errorf("expected trace_id field in output, got: %s", buf.String())
	}
}

// TestWithTraceFromContext_NoTrace confirms that the original logger is returned
// unchanged when no trace ID is in the context.
func TestWithTraceFromContext_NoTrace(t *testing.T) {
	l, _ := newTestLogger(t, "text")
	if same := logging.WithTraceFromContext(context.Background(), l); same == nil {
		t.Fatal("WithTraceFromContext with no trace ID returned nil")
	}
}

func BenchmarkLogger_InfoWithTrace(b *testing.B) {
	l := logging.NewLogger(logging.Config{Level: "info", Format: "json", Output: io.Discard})
	ctx := logging.WithTraceID(context.Background(), "bench-trace-id")
	b.ReportAllocs()
	// b.Loop() (Go 1.24+) handles timer reset automatically.
	for b.Loop() {
		enriched := logging.WithTraceFromContext(ctx, l)
		enriched.Info("request received", "method", "GET", "path", "/api/v1/resource")
	}
}

func BenchmarkLogger_With(b *testing.B) {
	l := logging.NewLogger(logging.Config{Level: "info", Format: "json", Output: io.Discard})
	b.ReportAllocs()
	// b.Loop() (Go 1.24+) handles timer reset automatically.
	for b.Loop() {
		_ = l.With("request_id", "abc123", "trace_id", "xyz")
	}
}
