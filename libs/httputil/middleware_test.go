//go:build unit

package httputil_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
)

func newTestLogger() httputil.Logger {
	return logging.NewLogger(logging.Config{Level: "debug", Format: "text"})
}

func TestTraceIDMiddleware_GeneratesID(t *testing.T) {
	handler := httputil.TraceIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	traceID := w.Header().Get("X-Trace-ID")
	if traceID == "" {
		t.Fatal("expected X-Trace-ID header to be set")
	}
}

func TestTraceIDMiddleware_UsesExistingID(t *testing.T) {
	const existingID = "my-trace-id-123"
	handler := httputil.TraceIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Trace-ID", existingID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got := w.Header().Get("X-Trace-ID"); got != existingID {
		t.Fatalf("expected %s, got %s", existingID, got)
	}
}

func TestLoggingMiddleware(t *testing.T) {
	logger := newTestLogger()
	mw := httputil.LoggingMiddleware(logger)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	logger := newTestLogger()
	mw := httputil.RecoveryMiddleware(logger)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 after panic recovery, got %d", w.Code)
	}
}
