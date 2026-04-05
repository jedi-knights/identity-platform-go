// Package identityservice implements the auth-server's UserAuthenticator port by
// delegating to identity-service over HTTP.
package identityservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
}

// UserAuthenticator implements ports.UserAuthenticator by calling identity-service.
type UserAuthenticator struct {
	baseURL    string
	httpClient *http.Client
}

// NewUserAuthenticator returns a UserAuthenticator that calls the given base URL.
func NewUserAuthenticator(baseURL string, httpClient *http.Client) *UserAuthenticator {
	return &UserAuthenticator{baseURL: baseURL, httpClient: httpClient}
}

// VerifyCredentials posts the user's credentials to identity-service POST /auth/login.
// Returns the user's ID on success.
func (a *UserAuthenticator) VerifyCredentials(ctx context.Context, email, password string) (_ string, retErr error) {
	body, err := json.Marshal(loginRequest{Email: email, Password: password})
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "marshalling login request", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/auth/login", bytes.NewReader(body))
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "building login request", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "identity-service unavailable", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing login response body", err)
		}
	}()

	return parseLoginResponse(resp)
}

// parseLoginResponse checks the status code, decodes the login response, and
// returns the user's ID. Extracted from VerifyCredentials to keep its cyclomatic
// complexity within bounds.
func parseLoginResponse(resp *http.Response) (string, error) {
	if resp.StatusCode == http.StatusUnauthorized {
		return "", apperrors.New(apperrors.ErrCodeUnauthorized, "invalid user credentials")
	}
	if resp.StatusCode != http.StatusOK {
		return "", apperrors.New(apperrors.ErrCodeInternal, fmt.Sprintf("identity-service returned %d", resp.StatusCode))
	}
	var lr loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "decoding login response", err)
	}
	return lr.UserID, nil
}
