// Package policyservice provides an HTTP client adapter for the
// authorization-policy-service permissions endpoint.
package policyservice

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// Compile-time interface check.
var _ ports.SubjectPermissionsFetcher = (*Client)(nil)

// Client calls GET /subjects/{subjectID}/permissions on the authorization-policy-service.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// New returns a Client targeting the given base URL.
func New(baseURL string) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

type subjectPermissionsResponse struct {
	SubjectID   string   `json:"subject_id"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// permissionsStatusResult interprets the HTTP status from the policy service.
// ok==true means the caller should proceed to decode the body.
// ok==false with err==nil means the subject has no policy (404) — not an error.
// ok==false with err!=nil means an unexpected failure.
func permissionsStatusResult(status int, subjectID string) (ok bool, err error) {
	switch status {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		// Subject has no policy entry — not an error condition.
		return false, nil
	default:
		return false, fmt.Errorf("policy service returned %d for subject %q", status, subjectID)
	}
}

// GetSubjectPermissions fetches roles and permissions for subjectID.
// Returns empty slices (not an error) when the subject has no policy.
func (c *Client) GetSubjectPermissions(ctx context.Context, subjectID string) (_ []string, _ []string, retErr error) {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing policy service base URL: %w", err)
	}
	// Set RawPath so the percent-encoded form is preserved over the wire;
	// Path is the decoded form used by the URL package internally.
	base.Path = "/subjects/" + subjectID + "/permissions"
	base.RawPath = "/subjects/" + url.PathEscape(subjectID) + "/permissions"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating permissions request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("calling policy service: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil && retErr == nil {
			retErr = fmt.Errorf("closing permissions response body: %w", err)
		}
	}()

	ok, err := permissionsStatusResult(resp.StatusCode, subjectID)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, nil
	}

	var result subjectPermissionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, fmt.Errorf("decoding permissions response: %w", err)
	}

	return result.Roles, result.Permissions, nil
}
