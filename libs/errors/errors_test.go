package errors_test

import (
	"fmt"
	"net/http"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
)

func TestNew(t *testing.T) {
	err := apperrors.New(apperrors.ErrCodeNotFound, "item not found")
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Code != apperrors.ErrCodeNotFound {
		t.Fatalf("expected NOT_FOUND, got %s", err.Code)
	}
	if err.Message != "item not found" {
		t.Fatalf("unexpected message: %s", err.Message)
	}
}

func TestWrap(t *testing.T) {
	cause := fmt.Errorf("db error")
	err := apperrors.Wrap(apperrors.ErrCodeInternal, "database failure", cause)
	if err.Err != cause {
		t.Fatal("expected wrapped error to be cause")
	}
	if err.Unwrap() != cause {
		t.Fatal("Unwrap should return cause")
	}
}

func TestAppError_Error(t *testing.T) {
	err := apperrors.New(apperrors.ErrCodeBadRequest, "bad input")
	s := err.Error()
	if s == "" {
		t.Fatal("expected non-empty error string")
	}

	wrapped := apperrors.Wrap(apperrors.ErrCodeInternal, "wrapped", fmt.Errorf("underlying"))
	if wrapped.Error() == "" {
		t.Fatal("expected non-empty error string for wrapped error")
	}
}

func TestIsNotFound(t *testing.T) {
	err := apperrors.New(apperrors.ErrCodeNotFound, "not found")
	if !apperrors.IsNotFound(err) {
		t.Fatal("expected IsNotFound to return true")
	}
	other := apperrors.New(apperrors.ErrCodeInternal, "internal")
	if apperrors.IsNotFound(other) {
		t.Fatal("expected IsNotFound to return false for non-not-found error")
	}
}

func TestIsUnauthorized(t *testing.T) {
	err := apperrors.New(apperrors.ErrCodeUnauthorized, "unauthorized")
	if !apperrors.IsUnauthorized(err) {
		t.Fatal("expected IsUnauthorized to return true")
	}
}

func TestIsForbidden(t *testing.T) {
	err := apperrors.New(apperrors.ErrCodeForbidden, "forbidden")
	if !apperrors.IsForbidden(err) {
		t.Fatal("expected IsForbidden to return true")
	}
}

func TestIsBadRequest(t *testing.T) {
	err := apperrors.New(apperrors.ErrCodeBadRequest, "bad request")
	if !apperrors.IsBadRequest(err) {
		t.Fatal("expected IsBadRequest to return true")
	}
}

func TestHTTPStatus(t *testing.T) {
	tests := []struct {
		name     string
		code     apperrors.ErrorCode
		expected int
	}{
		{"not found", apperrors.ErrCodeNotFound, http.StatusNotFound},
		{"unauthorized", apperrors.ErrCodeUnauthorized, http.StatusUnauthorized},
		{"forbidden", apperrors.ErrCodeForbidden, http.StatusForbidden},
		{"bad request", apperrors.ErrCodeBadRequest, http.StatusBadRequest},
		{"conflict", apperrors.ErrCodeConflict, http.StatusConflict},
		{"internal", apperrors.ErrCodeInternal, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := apperrors.New(tt.code, "msg")
			got := apperrors.HTTPStatus(err)
			if got != tt.expected {
				t.Errorf("code %s: expected %d, got %d", tt.code, tt.expected, got)
			}
		})
	}
}

func TestHTTPStatus_NonAppError(t *testing.T) {
	err := fmt.Errorf("plain error")
	got := apperrors.HTTPStatus(err)
	if got != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", got)
	}
}
