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
	_, _ = buf.WriteTo(w)
}

// WriteError writes a JSON error response derived from err.
// It uses apperrors.HTTPStatus to determine the status code.
// For non-AppError values, a generic sanitized message is returned to prevent
// internal details (SQL errors, file paths, etc.) from leaking to clients.
func WriteError(w http.ResponseWriter, err error) {
	status := apperrors.HTTPStatus(err)

	var ae *apperrors.AppError
	var resp ErrorResponse
	if errors.As(err, &ae) {
		resp = ErrorResponse{Error: ae.Message, Code: string(ae.Code)}
	} else {
		resp = ErrorResponse{Error: "internal server error", Code: string(apperrors.ErrCodeInternal)}
	}

	WriteJSON(w, status, resp)
}
