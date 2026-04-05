package httputil_test

import (
	"encoding/json"
	"errors"
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
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if body["hello"] != "world" {
		t.Errorf("unexpected body: %v", body)
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
	httputil.WriteError(w, errors.New("something went wrong"))

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
	if resp.Error == "something went wrong" {
		t.Error("raw error message must not be exposed to clients")
	}
}

func TestHTTPStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"not found", apperrors.New(apperrors.ErrCodeNotFound, "msg"), http.StatusNotFound},
		{"unauthorized", apperrors.New(apperrors.ErrCodeUnauthorized, "msg"), http.StatusUnauthorized},
		{"forbidden", apperrors.New(apperrors.ErrCodeForbidden, "msg"), http.StatusForbidden},
		{"bad request", apperrors.New(apperrors.ErrCodeBadRequest, "msg"), http.StatusBadRequest},
		{"conflict", apperrors.New(apperrors.ErrCodeConflict, "msg"), http.StatusConflict},
		{"internal", apperrors.New(apperrors.ErrCodeInternal, "msg"), http.StatusInternalServerError},
		{"plain error", errors.New("plain"), http.StatusInternalServerError},
		{"wrapped not-found", fmt.Errorf("outer: %w", apperrors.New(apperrors.ErrCodeNotFound, "inner")), http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := httputil.HTTPStatus(tt.err); got != tt.want {
				t.Errorf("HTTPStatus() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestHTTPStatus_NilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("HTTPStatus(nil) should panic but did not")
		}
	}()
	httputil.HTTPStatus(nil)
}

func BenchmarkWriteJSON(b *testing.B) {
	payload := map[string]string{"hello": "world"}
	b.ReportAllocs()
	// b.Loop() (Go 1.24+) handles timer reset automatically.
	for b.Loop() {
		w := httptest.NewRecorder()
		httputil.WriteJSON(w, http.StatusOK, payload)
	}
}

func BenchmarkWriteError(b *testing.B) {
	err := apperrors.New(apperrors.ErrCodeNotFound, "resource not found")
	b.ReportAllocs()
	// b.Loop() (Go 1.24+) handles timer reset automatically.
	for b.Loop() {
		w := httptest.NewRecorder()
		httputil.WriteError(w, err)
	}
}
