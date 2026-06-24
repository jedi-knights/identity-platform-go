// Package authserver is login-ui's HTTP adapter for auth-server. It
// implements ports.AuthCodeIssuer by calling auth-server's bearer-
// authenticated POST /internal/issue-code endpoint.
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

var _ ports.AuthCodeIssuer = (*IssueCodeClient)(nil)

// IssueCodeClient calls auth-server's /internal/issue-code endpoint. The
// service token is held in memory; comparison is auth-server-side. The
// adapter is safe for concurrent use.
type IssueCodeClient struct {
	baseURL      string
	serviceToken string
	httpClient   *http.Client
}

// NewIssueCodeClient returns a client wired to baseURL +
// /internal/issue-code. serviceToken must match auth-server's
// AUTH_LOGIN_UI_SERVICE_TOKEN.
func NewIssueCodeClient(baseURL, serviceToken string, httpClient *http.Client) *IssueCodeClient {
	return &IssueCodeClient{baseURL: baseURL, serviceToken: serviceToken, httpClient: httpClient}
}

type issueCodeRequestDTO struct {
	LoginChallenge string   `json:"login_challenge"`
	SessionID      string   `json:"session_id"`
	ConsentGranted []string `json:"consent_granted"`
}

type issueCodeResponseDTO struct {
	Code        string `json:"code"`
	RedirectURI string `json:"redirect_uri"`
	State       string `json:"state"`
}

// IssueCode POSTs to auth-server with the bearer service token and returns
// the decoded response. Any non-2xx maps to apperrors.ErrCodeInternal —
// login-ui treats an unsuccessful issue-code as a generic sign-in failure.
func (c *IssueCodeClient) IssueCode(ctx context.Context, in ports.IssueCodeRequest) (_ *ports.IssueCodeResponse, retErr error) {
	body, err := json.Marshal(issueCodeRequestDTO{
		LoginChallenge: in.LoginChallenge,
		SessionID:      in.SessionID,
		ConsentGranted: in.ConsentGranted,
	})
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "marshalling issue-code request", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/internal/issue-code", bytes.NewReader(body))
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "building issue-code request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.serviceToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "auth-server unavailable", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing issue-code response body", cerr)
		}
	}()
	return parseIssueCodeResponse(resp)
}

func parseIssueCodeResponse(resp *http.Response) (*ports.IssueCodeResponse, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, apperrors.New(apperrors.ErrCodeInternal, fmt.Sprintf("auth-server returned %d", resp.StatusCode))
	}
	var dto issueCodeResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&dto); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "decoding issue-code response", err)
	}
	if dto.Code == "" || dto.RedirectURI == "" {
		return nil, apperrors.New(apperrors.ErrCodeInternal, "auth-server returned empty code or redirect_uri")
	}
	return &ports.IssueCodeResponse{
		Code:        dto.Code,
		RedirectURI: dto.RedirectURI,
		State:       dto.State,
	}, nil
}
