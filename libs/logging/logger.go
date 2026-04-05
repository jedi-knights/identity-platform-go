package logging

import (
	"context"
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

// defaultLogger is returned by FromContext when no logger is in the context.
var defaultLogger = NewLogger(Config{Level: "info", Format: "text"})

// FromContext returns the Logger stored in the context, or a default logger.
func FromContext(ctx context.Context) Logger {
	if l, ok := ctx.Value(loggerKey).(Logger); ok {
		return l
	}
	return defaultLogger
}

// slogLogger wraps *slog.Logger and always includes service/environment fields.
type slogLogger struct {
	inner       *slog.Logger
	serviceName string
	environment string
}

// NewLogger creates a new Logger from the provided Config.
func NewLogger(config Config) Logger {
	opts := &slog.HandlerOptions{Level: parseLogLevel(config.Level)}
	handler := newHandler(config.Format, opts)

	attrs := []any{}
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

	return &slogLogger{
		inner:       inner,
		serviceName: config.ServiceName,
		environment: config.Environment,
	}
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func newHandler(format string, opts *slog.HandlerOptions) slog.Handler {
	if format == "json" {
		return slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.NewTextHandler(os.Stdout, opts)
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
