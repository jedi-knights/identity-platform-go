package httputil_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
)

func newTestLogger(t *testing.T) httputil.Logger {
	t.Helper()
	return logging.NewLogger(logging.Config{Level: "debug", Format: "text", Output: io.Discard})
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
	// A canonical UUID v4: version nibble = 4, variant nibble = a (in [89ab]).
	const existingID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	var capturedContextID string
	handler := httputil.TraceIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedContextID = logging.TraceIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Trace-ID", existingID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got := w.Header().Get("X-Trace-ID"); got != existingID {
		t.Fatalf("response header X-Trace-ID = %q, want %q", got, existingID)
	}
	if capturedContextID != existingID {
		t.Errorf("context trace ID = %q, want %q", capturedContextID, existingID)
	}
}

func TestLoggingMiddleware(t *testing.T) {
	logger := newTestLogger(t)
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

// TestLoggingMiddleware_NoWrite confirms that a handler that calls neither Write
// nor WriteHeader does not cause a panic and does not log status 0.
func TestLoggingMiddleware_NoWrite(t *testing.T) {
	logger := newTestLogger(t)
	mw := httputil.LoggingMiddleware(logger)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// intentionally writes nothing
	}))

	req := httptest.NewRequest(http.MethodGet, "/empty", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req) // must not panic
}

func TestRecoveryMiddleware(t *testing.T) {
	logger := newTestLogger(t)
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

// TestRecoveryMiddleware_PanicAfterWrite documents that when a handler calls
// Write (without an explicit WriteHeader) before panicking, the recovery must
// not attempt a second response — the implicitly committed 200 must be preserved.
func TestRecoveryMiddleware_PanicAfterWrite(t *testing.T) {
	logger := newTestLogger(t)
	mw := httputil.RecoveryMiddleware(logger)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("partial")) // implicit 200, no explicit WriteHeader
		panic("panic after Write")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Recovery must not overwrite the already-committed response with 500.
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — recovery overwrote a committed response", w.Code)
	}
}

// TestRecoveryMiddleware_PanicAfterWriteHeader documents that when a handler
// calls WriteHeader before panicking, the recovery must not attempt a second
// response — the original status must be preserved.
func TestRecoveryMiddleware_PanicAfterWriteHeader(t *testing.T) {
	logger := newTestLogger(t)
	mw := httputil.RecoveryMiddleware(logger)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		panic("panic after WriteHeader")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// The handler committed 200 before panicking; recovery must not overwrite it with 500.
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (from handler), got %d — recovery must not overwrite a committed response", w.Code)
	}
}

func TestUUIDPatternAcceptance(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		wantEcho bool // true = middleware echoes the ID back; false = new UUID generated
	}{
		{"valid v4 variant a", "f47ac10b-58cc-4372-a567-0e02b2c3d479", true},
		{"valid v4 variant 8", "550e8400-e29b-4d0f-8716-446655440000", true},
		{"valid v4 variant b", "550e8400-e29b-4d0f-b716-446655440000", true},
		{"empty", "", false},
		{"too short", "550e8400-e29b-4d0f-a716", false},
		{"uppercase hex", "F47AC10B-58CC-4372-A567-0E02B2C3D479", false},
		{"version 1", "550e8400-e29b-1d0f-a716-446655440000", false},
		{"version 3", "550e8400-e29b-3d0f-a716-446655440000", false},
		{"invalid variant c", "550e8400-e29b-4d0f-c716-446655440000", false},
		{"sql injection", "'; DROP TABLE users; --", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := httputil.TraceIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.id != "" {
				req.Header.Set("X-Trace-ID", tt.id)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			got := w.Header().Get("X-Trace-ID")
			if tt.wantEcho {
				if got != tt.id {
					t.Errorf("X-Trace-ID = %q, want echo of %q", got, tt.id)
				}
			} else {
				if got == tt.id {
					t.Errorf("invalid ID %q was echoed back; want a freshly generated UUID", tt.id)
				}
				if got == "" {
					t.Error("X-Trace-ID must always be set, even when input is rejected")
				}
			}
		})
	}
}
