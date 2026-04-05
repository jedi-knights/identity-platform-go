// Package policyservice provides an HTTP client adapter for the
// authorization-policy-service permissions endpoint.
package policyservice

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

// GetSubjectPermissions fetches roles and permissions for subjectID.
// Returns empty slices (not an error) when the subject has no policy.
func (c *Client) GetSubjectPermissions(ctx context.Context, subjectID string) (_ []string, _ []string, retErr error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/subjects/"+subjectID+"/permissions", nil)
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

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("policy service returned %d for subject %q", resp.StatusCode, subjectID)
	}

	var result subjectPermissionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, fmt.Errorf("decoding permissions response: %w", err)
	}

	return result.Roles, result.Permissions, nil
}
