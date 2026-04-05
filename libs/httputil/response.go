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
func WriteError(w http.ResponseWriter, err error) {
	status := apperrors.HTTPStatus(err)
	resp := ErrorResponse{Error: err.Error()}

	var ae *apperrors.AppError
	if asAppErr(err, &ae) {
		resp.Code = string(ae.Code)
		resp.Error = ae.Message
	}

	WriteJSON(w, status, resp)
}

// asAppErr is a helper that attempts to unwrap err into *apperrors.AppError.
func asAppErr(err error, target **apperrors.AppError) bool {
	return errors.As(err, target)
}
