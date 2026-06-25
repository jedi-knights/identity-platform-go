// Package identityservice is login-ui's HTTP adapter for identity-service.
// It implements ports.UserAuthenticator by calling identity-service's
// POST /auth/login endpoint and mapping the response to a subject ID.
package identityservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// Compile-time check — drift between the adapter and the port surfaces at
// build time rather than at runtime.
var _ ports.UserAuthenticator = (*Authenticator)(nil)

// Authenticator calls identity-service's /auth/login over HTTP. The base URL
// must NOT include /auth/login itself; the adapter appends the path.
type Authenticator struct {
	baseURL    string
	httpClient *http.Client
}

// NewAuthenticator returns an Authenticator that posts to baseURL +
// /auth/login on every VerifyCredentials call.
func NewAuthenticator(baseURL string, httpClient *http.Client) *Authenticator {
	return &Authenticator{baseURL: baseURL, httpClient: httpClient}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	UserID string `json:"user_id"`
}

// VerifyCredentials POSTs to identity-service /auth/login and returns the
// returned user_id as the subject ID. A 401 is mapped to
// apperrors.ErrCodeUnauthorized; every other non-2xx and any transport
// failure is mapped to apperrors.ErrCodeInternal.
func (a *Authenticator) VerifyCredentials(ctx context.Context, email, password string) (_ string, retErr error) {
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
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing login response body", cerr)
		}
	}()
	return parseLoginResponse(resp)
}

// parseLoginResponse decodes the success body or maps the error status. Split
// out to keep VerifyCredentials within the project's cyclomatic-complexity
// budget.
func parseLoginResponse(resp *http.Response) (string, error) {
	switch resp.StatusCode {
	case http.StatusOK:
		var lr loginResponse
		if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
			return "", apperrors.Wrap(apperrors.ErrCodeInternal, "decoding login response", err)
		}
		if lr.UserID == "" {
			return "", apperrors.New(apperrors.ErrCodeInternal, "identity-service returned empty user_id")
		}
		return lr.UserID, nil
	case http.StatusUnauthorized:
		return "", apperrors.New(apperrors.ErrCodeUnauthorized, "invalid email or password")
	default:
		return "", apperrors.New(apperrors.ErrCodeInternal, fmt.Sprintf("identity-service returned %d", resp.StatusCode))
	}
}
