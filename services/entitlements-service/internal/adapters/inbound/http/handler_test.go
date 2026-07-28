package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/application"
)

func testLogger() logging.Logger {
	return logging.New(logging.Config{Level: "error", Format: "json", Environment: "test"})
}

func newHandler() *http.Handler {
	repo := memory.NewAccountRepository()
	svc := application.NewAccountService(repo).
		WithAudit(audit.New(audit.NoopSink{}), "entitlements-service")
	return http.NewHandler(svc, testLogger())
}

func postJSON(t *testing.T, handler *http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(stdhttp.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	http.NewRouter(handler, testLogger()).ServeHTTP(w, req)
	return w
}

func TestCreatePersonalAccount_Returns201WithAccountID(t *testing.T) {
	// Arrange
	handler := newHandler()

	// Act
	w := postJSON(t, handler, "/accounts/personal",
		`{"user_id":"user-1","email":"u1@example.com"}`)

	// Assert
	if w.Code != stdhttp.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["account_id"] == "" {
		t.Errorf("expected non-empty account_id, got %v", resp["account_id"])
	}
	if resp["billing_email"] != "u1@example.com" {
		t.Errorf("billing_email = %v, want u1@example.com", resp["billing_email"])
	}
}

func TestCreatePersonalAccount_IdempotentReturns200OnRepeat(t *testing.T) {
	// Arrange
	handler := newHandler()

	// Act
	first := postJSON(t, handler, "/accounts/personal",
		`{"user_id":"user-1","email":"u1@example.com"}`)
	second := postJSON(t, handler, "/accounts/personal",
		`{"user_id":"user-1","email":"u1@example.com"}`)

	// Assert — first call creates (201), second returns existing (200);
	// distinct status codes let the caller tell "created" from "already
	// existed" without a parallel probe.
	if first.Code != stdhttp.StatusCreated {
		t.Errorf("first call: status = %d, want 201", first.Code)
	}
	if second.Code != stdhttp.StatusOK {
		t.Errorf("second call: status = %d, want 200", second.Code)
	}

	var firstBody, secondBody map[string]any
	_ = json.Unmarshal(first.Body.Bytes(), &firstBody)
	_ = json.Unmarshal(second.Body.Bytes(), &secondBody)
	if firstBody["account_id"] != secondBody["account_id"] {
		t.Errorf("expected same account_id, got %v and %v", firstBody["account_id"], secondBody["account_id"])
	}
}

func TestCreatePersonalAccount_400OnMissingUserID(t *testing.T) {
	// Arrange
	handler := newHandler()

	// Act
	w := postJSON(t, handler, "/accounts/personal",
		`{"email":"u1@example.com"}`)

	// Assert
	if w.Code != stdhttp.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCreatePersonalAccount_400OnMissingEmail(t *testing.T) {
	// Arrange
	handler := newHandler()

	// Act
	w := postJSON(t, handler, "/accounts/personal",
		`{"user_id":"user-1"}`)

	// Assert
	if w.Code != stdhttp.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCreatePersonalAccount_400OnMalformedJSON(t *testing.T) {
	// Arrange
	handler := newHandler()

	// Act
	w := postJSON(t, handler, "/accounts/personal", `{not-json`)

	// Assert
	if w.Code != stdhttp.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCreatePersonalAccount_405OnGet(t *testing.T) {
	// Arrange
	handler := newHandler()

	// Act
	req := httptest.NewRequest(stdhttp.MethodGet, "/accounts/personal", nil)
	w := httptest.NewRecorder()
	http.NewRouter(handler, testLogger()).ServeHTTP(w, req)

	// Assert
	if w.Code != stdhttp.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHealth_Returns200(t *testing.T) {
	// Arrange
	handler := newHandler()

	// Act
	req := httptest.NewRequest(stdhttp.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	http.NewRouter(handler, testLogger()).ServeHTTP(w, req)

	// Assert
	if w.Code != stdhttp.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// silence unused-context imports linters when the file is re-parsed.
var _ = context.Background
var _ = bytes.NewReader
