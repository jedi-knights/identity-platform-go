package errors_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		code    apperrors.ErrorCode
		message string
	}{
		{"not found", apperrors.ErrCodeNotFound, "item not found"},
		{"unauthorized", apperrors.ErrCodeUnauthorized, "access denied"},
		{"internal", apperrors.ErrCodeInternal, "server error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := apperrors.New(tt.code, tt.message)
			if err == nil {
				t.Fatal("expected non-nil error")
			}
			if err.Code != tt.code {
				t.Errorf("expected code %s, got %s", tt.code, err.Code)
			}
			if err.Message != tt.message {
				t.Errorf("expected message %q, got %q", tt.message, err.Message)
			}
			if err.Err != nil {
				t.Error("expected nil wrapped error")
			}
		})
	}
}

func TestWrap(t *testing.T) {
	cause := errors.New("db error")
	err := apperrors.Wrap(apperrors.ErrCodeInternal, "database failure", cause)
	if err.Unwrap() != cause {
		t.Fatal("Unwrap should return cause")
	}
	if err.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
}

func TestAppError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *apperrors.AppError
		want string
	}{
		{
			name: "without wrapped error",
			err:  apperrors.New(apperrors.ErrCodeBadRequest, "bad input"),
			want: "BAD_REQUEST: bad input",
		},
		{
			name: "with wrapped error",
			err:  apperrors.Wrap(apperrors.ErrCodeInternal, "wrapped", errors.New("underlying")),
			want: "INTERNAL: wrapped: underlying",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"direct not-found", apperrors.New(apperrors.ErrCodeNotFound, "not found"), true},
		{"wrapped not-found", fmt.Errorf("outer: %w", apperrors.New(apperrors.ErrCodeNotFound, "inner")), true},
		{"other code", apperrors.New(apperrors.ErrCodeInternal, "internal"), false},
		{"plain error", errors.New("plain"), false},
		{"nil error", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apperrors.IsNotFound(tt.err); got != tt.want {
				t.Errorf("IsNotFound() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsUnauthorized(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"unauthorized", apperrors.New(apperrors.ErrCodeUnauthorized, "unauthorized"), true},
		{"wrapped unauthorized", fmt.Errorf("outer: %w", apperrors.New(apperrors.ErrCodeUnauthorized, "inner")), true},
		{"not found", apperrors.New(apperrors.ErrCodeNotFound, "not found"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apperrors.IsUnauthorized(tt.err); got != tt.want {
				t.Errorf("IsUnauthorized() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsForbidden(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"forbidden", apperrors.New(apperrors.ErrCodeForbidden, "forbidden"), true},
		{"wrapped forbidden", fmt.Errorf("outer: %w", apperrors.New(apperrors.ErrCodeForbidden, "inner")), true},
		{"not found", apperrors.New(apperrors.ErrCodeNotFound, "not found"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apperrors.IsForbidden(tt.err); got != tt.want {
				t.Errorf("IsForbidden() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsBadRequest(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"bad request", apperrors.New(apperrors.ErrCodeBadRequest, "bad request"), true},
		{"wrapped bad request", fmt.Errorf("outer: %w", apperrors.New(apperrors.ErrCodeBadRequest, "inner")), true},
		{"not found", apperrors.New(apperrors.ErrCodeNotFound, "not found"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apperrors.IsBadRequest(tt.err); got != tt.want {
				t.Errorf("IsBadRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsConflict(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"conflict error", apperrors.New(apperrors.ErrCodeConflict, "conflict"), true},
		{"wrapped conflict", fmt.Errorf("outer: %w", apperrors.New(apperrors.ErrCodeConflict, "inner")), true},
		{"not found error", apperrors.New(apperrors.ErrCodeNotFound, "not found"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apperrors.IsConflict(tt.err); got != tt.want {
				t.Errorf("IsConflict() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsInternal(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"internal error", apperrors.New(apperrors.ErrCodeInternal, "internal"), true},
		{"wrapped internal", fmt.Errorf("outer: %w", apperrors.New(apperrors.ErrCodeInternal, "inner")), true},
		{"not found error", apperrors.New(apperrors.ErrCodeNotFound, "not found"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apperrors.IsInternal(tt.err); got != tt.want {
				t.Errorf("IsInternal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTPStatus(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{"not found", apperrors.New(apperrors.ErrCodeNotFound, "msg"), http.StatusNotFound},
		{"unauthorized", apperrors.New(apperrors.ErrCodeUnauthorized, "msg"), http.StatusUnauthorized},
		{"forbidden", apperrors.New(apperrors.ErrCodeForbidden, "msg"), http.StatusForbidden},
		{"bad request", apperrors.New(apperrors.ErrCodeBadRequest, "msg"), http.StatusBadRequest},
		{"conflict", apperrors.New(apperrors.ErrCodeConflict, "msg"), http.StatusConflict},
		{"internal", apperrors.New(apperrors.ErrCodeInternal, "msg"), http.StatusInternalServerError},
		{"plain error", errors.New("plain"), http.StatusInternalServerError},
		{"nil error", nil, http.StatusInternalServerError},
		{"wrapped not-found", fmt.Errorf("outer: %w", apperrors.New(apperrors.ErrCodeNotFound, "inner")), http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apperrors.HTTPStatus(tt.err); got != tt.expected {
				t.Errorf("HTTPStatus() = %d, want %d", got, tt.expected)
			}
		})
	}
}
