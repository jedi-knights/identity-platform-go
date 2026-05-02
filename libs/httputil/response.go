package httputil

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
)

// ErrorResponse is the JSON body returned for error responses.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// WriteJSON encodes v as JSON and writes it with the given HTTP status.
// Encoding happens into a buffer before any headers are sent, so if encoding
// fails the client receives a 500 rather than a 200 with a truncated body.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := buf.WriteTo(w); err != nil {
		// Headers are already sent; log the transport failure but cannot change the response.
		slog.Error("failed to write response body", "error", err)
	}
}

// appErrorHTTPStatus maps every predeclared AppError code to its HTTP status.
// All codes from libs/errors must appear here; the default branch in HTTPStatus
// is a safety net for unknown future codes, not a substitute for known ones.
var appErrorHTTPStatus = map[apperrors.ErrorCode]int{
	apperrors.ErrCodeNotFound:     http.StatusNotFound,
	apperrors.ErrCodeUnauthorized: http.StatusUnauthorized,
	apperrors.ErrCodeForbidden:    http.StatusForbidden,
	apperrors.ErrCodeBadRequest:   http.StatusBadRequest,
	apperrors.ErrCodeConflict:     http.StatusConflict,
	apperrors.ErrCodeInternal:     http.StatusInternalServerError,
	apperrors.ErrCodeRateLimit:    http.StatusTooManyRequests,
	apperrors.ErrCodeUnavailable:  http.StatusServiceUnavailable,
}

// HTTPStatus maps an AppError code to an HTTP status code.
// It panics if err is nil — nil signals success and must never be passed here.
// Non-AppError, non-nil values and unrecognised codes return 500.
func HTTPStatus(err error) int {
	if err == nil {
		panic("httputil.HTTPStatus called with nil — nil is success, not an error")
	}
	var e *apperrors.AppError
	if !errors.As(err, &e) {
		return http.StatusInternalServerError
	}
	if status, ok := appErrorHTTPStatus[e.Code()]; ok {
		return status
	}
	return http.StatusInternalServerError
}

// WriteError writes a JSON error response derived from err.
// It uses HTTPStatus to determine the status code.
// For non-AppError values, a generic sanitized message is returned to prevent
// internal details (SQL errors, file paths, etc.) from leaking to clients.
// WriteError must not be called with a nil error.
func WriteError(w http.ResponseWriter, err error) {
	status := HTTPStatus(err)

	var ae *apperrors.AppError
	var resp ErrorResponse
	if errors.As(err, &ae) {
		resp = ErrorResponse{Error: ae.Message(), Code: string(ae.Code())}
	} else {
		resp = ErrorResponse{Error: "internal server error", Code: string(apperrors.ErrCodeInternal)}
	}

	WriteJSON(w, status, resp)
}
