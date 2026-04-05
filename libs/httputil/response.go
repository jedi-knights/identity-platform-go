package httputil

import (
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
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
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
