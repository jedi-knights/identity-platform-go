package httputil

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ocrosby/identity-platform-go/libs/logging"
)

// Logger is an alias for the logging.Logger interface used throughout httputil.
type Logger = logging.Logger

const traceIDHeader = "X-Trace-ID"

// uuidPattern matches a well-formed UUID v4 string.
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// newUUID generates a random UUID v4 using crypto/rand.
// It panics if crypto/rand is unavailable — this indicates a broken system
// environment where generating secure trace IDs is impossible.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("newUUID: crypto/rand unavailable: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	// Use plain %x without width padding — each byte produces exactly 2 hex chars.
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// TraceIDMiddleware injects a trace ID into the request context.
// It reads X-Trace-ID from the inbound request header if it is a valid UUID v4,
// otherwise it generates a fresh one to prevent log-injection via crafted headers.
func TraceIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceID := r.Header.Get(traceIDHeader)
		if !uuidPattern.MatchString(traceID) {
			// Reject missing, malformed, or potentially injected trace IDs.
			traceID = newUUID()
		}
		ctx := logging.WithTraceID(r.Context(), traceID)
		w.Header().Set(traceIDHeader, traceID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code and track
// whether the response header has been committed.
type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.wroteHeader = true
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		// Explicitly call WriteHeader(200) through the wrapper so that both the
		// wrapper state (status, wroteHeader) and the underlying ResponseWriter
		// are committed via a single canonical path.
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// LoggingMiddleware returns middleware that logs each request/response.
//
// It reads trace_id and request_id from the request context, so it must be
// placed INNER to TraceIDMiddleware and RequestIDMiddleware in the chain:
//
//	TraceIDMiddleware → RequestIDMiddleware → LoggingMiddleware → handler
//
// Fields logged on every request: method, path, status, duration_ms,
// trace_id, request_id, remote_ip, user_agent.
func LoggingMiddleware(logger Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, status: 0}

			// Read correlation IDs from context — these are set by TraceIDMiddleware
			// and RequestIDMiddleware which must run before this middleware.
			ctx := r.Context()
			traceID := logging.TraceIDFromContext(ctx)
			requestID := logging.RequestIDFromContext(ctx)

			// Extract the client IP (last segment before the port in RemoteAddr).
			remoteIP := remoteIP(r.RemoteAddr)

			next.ServeHTTP(rw, r)
			if !rw.wroteHeader {
				// A handler that wrote nothing (no Write or WriteHeader call) will
				// have the net/http server default to 200. Record that here so the
				// log entry always carries a meaningful status and never logs 0.
				rw.status = http.StatusOK
			}

			duration := time.Since(start)
			l := logger.With(
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.status,
				"duration_ms", duration.Milliseconds(),
				"trace_id", traceID,
				"request_id", requestID,
				"remote_ip", remoteIP,
				"user_agent", r.UserAgent(),
			)
			l.Info("request completed")
		})
	}
}

// remoteIP extracts the IP address from a "host:port" RemoteAddr string.
func remoteIP(remoteAddr string) string {
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		return remoteAddr[:idx]
	}
	return remoteAddr
}

// RecoveryMiddleware returns middleware that recovers from panics and logs them.
// It wraps the ResponseWriter so it can detect whether a partial response was
// already written before the panic; if so, it skips calling http.Error to avoid
// writing conflicting headers or a double response body.
func RecoveryMiddleware(logger Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rw := &responseWriter{ResponseWriter: w}
			defer func() {
				if rec := recover(); rec != nil {
					ctx := r.Context()
					traceID := logging.TraceIDFromContext(ctx)
					logger.With("trace_id", traceID, "panic", fmt.Sprintf("%v", rec)).
						Error("recovered from panic")
					if !rw.wroteHeader {
						http.Error(rw, "internal server error", http.StatusInternalServerError)
					}
				}
			}()
			next.ServeHTTP(rw, r)
		})
	}
}
