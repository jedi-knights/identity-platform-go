// Package authserver: DeviceDecisionClient.
//
// Implements ports.DeviceDecider by calling auth-server's bearer-
// authenticated POST /internal/device/decision endpoint (ADR-0022) — the
// device-flow counterpart to IssueCodeClient's /internal/issue-code call.

package authserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

var _ ports.DeviceDecider = (*DeviceDecisionClient)(nil)

// DeviceDecisionClient calls auth-server's /internal/device/decision
// endpoint. The service token is held in memory; comparison is
// auth-server-side. The adapter is safe for concurrent use.
type DeviceDecisionClient struct {
	baseURL      string
	serviceToken string
	httpClient   *http.Client
}

// NewDeviceDecisionClient returns a client wired to baseURL +
// /internal/device/decision. serviceToken must match auth-server's
// AUTH_LOGIN_UI_SERVICE_TOKEN — the same shared secret IssueCodeClient uses.
func NewDeviceDecisionClient(baseURL, serviceToken string, httpClient *http.Client) *DeviceDecisionClient {
	return &DeviceDecisionClient{baseURL: baseURL, serviceToken: serviceToken, httpClient: httpClient}
}

type deviceDecisionRequestDTO struct {
	UserCode string `json:"user_code"`
	Subject  string `json:"subject"`
	Approved bool   `json:"approved"`
}

// Decide POSTs the decision to auth-server with the bearer service token.
// Any non-2xx maps to apperrors.ErrCodeInternal — login-ui treats an
// unsuccessful decision call as a generic "could not complete" failure.
func (c *DeviceDecisionClient) Decide(ctx context.Context, in ports.DeviceDecisionRequest) (retErr error) {
	body, err := json.Marshal(deviceDecisionRequestDTO{
		UserCode: in.UserCode,
		Subject:  in.Subject,
		Approved: in.Approved,
	})
	if err != nil {
		return apperrors.Wrap(apperrors.ErrCodeInternal, "marshalling device-decision request", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/internal/device/decision", bytes.NewReader(body))
	if err != nil {
		return apperrors.Wrap(apperrors.ErrCodeInternal, "building device-decision request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.serviceToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrCodeInternal, "auth-server unavailable", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing device-decision response body", cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return apperrors.New(apperrors.ErrCodeInternal, fmt.Sprintf("auth-server returned %d", resp.StatusCode))
	}
	return nil
}
