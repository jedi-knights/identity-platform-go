# libs/logging — Claude Context

## Purpose

`slog`-based structured logging with trace ID propagation and context-stored loggers. All services use this package for logging — never use `log.Printf` or `fmt.Print*` for application logging.

---

## Logger Interface

Services depend on the `Logger` interface, not on `*slogLogger`. This keeps the `slog` dependency contained and allows tests to inject a no-op logger (see `libs/testutil.NewTestLogger`).

```go
type Logger interface {
    Debug(msg string, args ...any)
    Info(msg string, args ...any)
    Warn(msg string, args ...any)
    Error(msg string, args ...any)
    With(args ...any) Logger
}
```

`With` returns a new `Logger` enriched with the given key-value pairs — it does not mutate the receiver. The returned value is always a `Logger`, never the concrete type.

---

## Context-Stored Logger

`WithContext` and `FromContext` allow a logger to be stored in and retrieved from a `context.Context`. This is the pattern used by HTTP middleware to propagate a request-scoped logger (already enriched with trace ID, service name, etc.) through to handlers.

`FromContext` never returns nil. When no logger is in context, it constructs a fallback info-level text logger with `"logger_source":"fallback"`. **Tests must inject a logger explicitly via `WithContext`** — the fallback's output is not capturable through any buffer.

---

## Trace ID Propagation

`WithTraceID` / `TraceIDFromContext` store and retrieve the trace ID as a plain string in context. `WithTraceFromContext` produces a logger enriched with the trace ID from the context — call this in handlers to get a per-request logger with the trace ID already attached.

The trace ID is set upstream by `libs/httputil.TraceIDMiddleware` before handlers run.

---

## Configuration

`NewLogger` accepts a `Config` struct. Unknown `Level` values default to `INFO` and log a warning at construction time — they do not panic. `Format` accepts `"json"` (production) or `"text"` (development); any other value produces text format.
