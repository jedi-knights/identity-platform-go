package http_test

import (
	"bytes"
	"encoding/json"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/inbound/http"
)

// bufferLogger returns a JSON logger and the buffer it writes to, so tests can
// assert on what an operator would see in the log stream.
func bufferLogger() (logging.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return logging.New(logging.Config{Level: "debug", Format: "json", Output: &buf}), &buf
}

func accessLogs(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("log output is not JSON: %v\n%s", err, buf.String())
		}
		if m["msg"] == "request completed" {
			out = append(out, m)
		}
	}
	return out
}

func TestRouter_EveryResponseCarriesTraceAndRequestIDs(t *testing.T) {
	// Arrange
	logger, _ := bufferLogger()
	router := http.NewRouter(newHandler(), logger)

	// Act
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(stdhttp.MethodGet, "/no-such-route", nil))

	// Assert
	if w.Header().Get("X-Trace-ID") == "" || w.Header().Get("X-Request-ID") == "" {
		t.Errorf("X-Trace-ID=%q X-Request-ID=%q, want both set even on a 404",
			w.Header().Get("X-Trace-ID"), w.Header().Get("X-Request-ID"))
	}
}

func TestRouter_AccessLogCarriesTheIDsTheClientSees(t *testing.T) {
	// Arrange
	logger, buf := bufferLogger()
	router := http.NewRouter(newHandler(), logger)
	req := httptest.NewRequest(stdhttp.MethodPost, "/accounts/personal",
		strings.NewReader(`{"user_id":"user-1","email":"u1@example.com"}`))
	req.Header.Set("Content-Type", "application/json")

	// Act
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	logs := accessLogs(t, buf)
	if len(logs) != 1 {
		t.Fatalf("got %d access log lines, want 1: %s", len(logs), buf.String())
	}
	if logs[0]["trace_id"] != w.Header().Get("X-Trace-ID") || logs[0]["request_id"] != w.Header().Get("X-Request-ID") {
		t.Errorf("log ids (%v, %v) != response header ids (%q, %q)",
			logs[0]["trace_id"], logs[0]["request_id"], w.Header().Get("X-Trace-ID"), w.Header().Get("X-Request-ID"))
	}
	if logs[0]["status"] != float64(stdhttp.StatusCreated) {
		t.Errorf("logged status = %v, want 201", logs[0]["status"])
	}
}

func TestRouter_HealthReportsOKWithoutAccessLogNoise(t *testing.T) {
	// Arrange
	logger, buf := bufferLogger()
	router := http.NewRouter(newHandler(), logger)

	// Act
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(stdhttp.MethodGet, "/health", nil))

	// Assert
	if w.Code != stdhttp.StatusOK || strings.TrimSpace(w.Body.String()) != `{"status":"ok"}` {
		t.Errorf("health = %d %q, want 200 {\"status\":\"ok\"}", w.Code, w.Body.String())
	}
	if n := len(accessLogs(t, buf)); n != 0 {
		t.Errorf("health checks produced %d access log lines, want 0", n)
	}
}
