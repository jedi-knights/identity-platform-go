package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// Logger defines the structured logging interface.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	With(args ...any) Logger
}

// Config holds configuration for creating a Logger.
type Config struct {
	Level       string
	Format      string // "json" or "text"
	ServiceName string
	Environment string
	Output      io.Writer // nil defaults to os.Stdout
}

type contextKey int

const (
	traceIDKey contextKey = iota
	loggerKey
)

// WithTraceID stores a trace ID in the context.
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDKey, traceID)
}

// TraceIDFromContext retrieves the trace ID from the context.
func TraceIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(traceIDKey).(string); ok {
		return v
	}
	return ""
}

// WithContext stores a Logger in the context.
func WithContext(ctx context.Context, l Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// FromContext returns the Logger stored in the context.
// If no logger is present it constructs a default info-level text logger.
// Prefer injecting loggers explicitly rather than relying on this fallback.
func FromContext(ctx context.Context) Logger {
	if l, ok := ctx.Value(loggerKey).(Logger); ok {
		return l
	}
	return NewLogger(Config{Level: "info", Format: "text"})
}

// slogLogger wraps *slog.Logger and always includes service/environment fields.
type slogLogger struct {
	inner       *slog.Logger
	serviceName string
	environment string
}

// NewLogger creates a new Logger from the provided Config.
// If Config.Level is not a recognised value, it defaults to INFO and logs a warning.
func NewLogger(config Config) Logger {
	level, ok := parseLogLevel(config.Level)
	opts := &slog.HandlerOptions{Level: level}
	handler := newHandler(config.Output, config.Format, opts)

	var attrs []any
	if config.ServiceName != "" {
		attrs = append(attrs, slog.String("service_name", config.ServiceName))
	}
	if config.Environment != "" {
		attrs = append(attrs, slog.String("environment", config.Environment))
	}

	inner := slog.New(handler)
	if len(attrs) > 0 {
		inner = inner.With(attrs...)
	}

	l := &slogLogger{
		inner:       inner,
		serviceName: config.ServiceName,
		environment: config.Environment,
	}

	if !ok && config.Level != "" {
		l.Warn("unknown log level, defaulting to INFO", "level", config.Level)
	}

	return l
}

// parseLogLevel converts a level string to slog.Level.
// Returns (level, true) on success, (LevelInfo, false) for unknown values.
func parseLogLevel(level string) (slog.Level, bool) {
	switch level {
	case "debug":
		return slog.LevelDebug, true
	case "warn":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	case "info", "":
		return slog.LevelInfo, true
	default:
		return slog.LevelInfo, false
	}
}

// newHandler creates a slog.Handler writing to w (os.Stdout if nil).
func newHandler(w io.Writer, format string, opts *slog.HandlerOptions) slog.Handler {
	if w == nil {
		w = os.Stdout
	}
	if format == "json" {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

func (l *slogLogger) Debug(msg string, args ...any) {
	l.inner.Debug(msg, args...)
}

func (l *slogLogger) Info(msg string, args ...any) {
	l.inner.Info(msg, args...)
}

func (l *slogLogger) Warn(msg string, args ...any) {
	l.inner.Warn(msg, args...)
}

func (l *slogLogger) Error(msg string, args ...any) {
	l.inner.Error(msg, args...)
}

func (l *slogLogger) With(args ...any) Logger {
	return &slogLogger{
		inner:       l.inner.With(args...),
		serviceName: l.serviceName,
		environment: l.environment,
	}
}

// WithTraceFromContext returns a Logger enriched with the trace ID from ctx.
func WithTraceFromContext(ctx context.Context, l Logger) Logger {
	traceID := TraceIDFromContext(ctx)
	if traceID == "" {
		return l
	}
	return l.With("trace_id", traceID)
}
