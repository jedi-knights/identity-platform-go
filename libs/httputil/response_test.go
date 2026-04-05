package httputil_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
)

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"hello": "world"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %s", ct)
	}
}

func TestWriteError_AppError(t *testing.T) {
	w := httptest.NewRecorder()
	err := apperrors.New(apperrors.ErrCodeNotFound, "resource not found")
	httputil.WriteError(w, err)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}

	var resp httputil.ErrorResponse
	if decErr := json.NewDecoder(w.Body).Decode(&resp); decErr != nil {
		t.Fatalf("failed to decode response: %v", decErr)
	}
	if resp.Code != string(apperrors.ErrCodeNotFound) {
		t.Fatalf("expected NOT_FOUND code, got %s", resp.Code)
	}
}

func TestWriteError_PlainError(t *testing.T) {
	w := httptest.NewRecorder()
	httputil.WriteError(w, fmt.Errorf("something went wrong"))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	var resp httputil.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Error != "internal server error" {
		t.Errorf("expected sanitized error message, got %q", resp.Error)
	}
	if w.Body.String() != "" && resp.Error == "something went wrong" {
		t.Error("raw error message must not be exposed to clients")
	}
}
