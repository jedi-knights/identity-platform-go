// Package entitlementsservice is identity-service's HTTP adapter for
// entitlements-service. It implements ports.EntitlementsAccountCreator
// by calling POST /accounts/personal and mapping the response to an
// account ID.
package entitlementsservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/ports"
)

// Compile-time check — drift between the adapter and the port surfaces
// at build time rather than at runtime.
var _ ports.EntitlementsAccountCreator = (*Creator)(nil)

// Creator posts to entitlements-service /accounts/personal on every
// CreatePersonalAccount call. baseURL must NOT include /accounts/personal
// — the adapter appends the path.
type Creator struct {
	baseURL    string
	httpClient *http.Client
}

// NewCreator returns a Creator that posts to baseURL + /accounts/personal.
// httpClient must be non-nil; supply a timeout-configured client at the
// composition root.
func NewCreator(baseURL string, httpClient *http.Client) *Creator {
	return &Creator{baseURL: baseURL, httpClient: httpClient}
}

type createRequest struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

type createResponse struct {
	AccountID    string `json:"account_id"`
	BillingEmail string `json:"billing_email"`
	UserID       string `json:"user_id"`
	Created      bool   `json:"created"`
}

// CreatePersonalAccount POSTs to entitlements-service. 201 and 200 are
// both success (created vs idempotent replay); any other status or a
// transport failure maps to ErrCodeInternal so the caller (Register)
// can fail closed per ADR-0019 accounting integrity.
func (c *Creator) CreatePersonalAccount(ctx context.Context, userID, email string) (_ string, retErr error) {
	body, err := json.Marshal(createRequest{UserID: userID, Email: email})
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "marshalling create request", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/accounts/personal", bytes.NewReader(body))
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "building create request", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "entitlements-service unavailable", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing create response body", cerr)
		}
	}()
	return parseCreateResponse(resp)
}

// parseCreateResponse decodes the success body or maps the error status.
// Split out to keep CreatePersonalAccount within the project's
// cyclomatic-complexity budget.
func parseCreateResponse(resp *http.Response) (string, error) {
	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		var cr createResponse
		if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
			return "", apperrors.Wrap(apperrors.ErrCodeInternal, "decoding create response", err)
		}
		if cr.AccountID == "" {
			return "", apperrors.New(apperrors.ErrCodeInternal, "entitlements-service returned empty account_id")
		}
		return cr.AccountID, nil
	case http.StatusBadRequest:
		return "", apperrors.New(apperrors.ErrCodeBadRequest, "entitlements-service rejected request")
	default:
		return "", apperrors.New(apperrors.ErrCodeInternal, fmt.Sprintf("entitlements-service returned %d", resp.StatusCode))
	}
}
