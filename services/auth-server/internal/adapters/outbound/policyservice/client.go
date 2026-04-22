// Package policyservice provides an HTTP client adapter for the
// authorization-policy-service permissions endpoint.
package policyservice

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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

// permissionsURL constructs the absolute URL for subjectID's permissions endpoint.
// Returns an error if subjectID contains path separators or traversal sequences.
func (c *Client) permissionsURL(subjectID string) (string, error) {
	if strings.ContainsAny(subjectID, "/\\") || strings.Contains(subjectID, "..") {
		return "", fmt.Errorf("subject ID %q is invalid: must not contain path separators or traversal sequences", subjectID)
	}
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("parsing policy service base URL: %w", err)
	}
	base.Path = "/subjects/" + subjectID + "/permissions"
	base.RawPath = "/subjects/" + url.PathEscape(subjectID) + "/permissions"
	return base.String(), nil
}

// closeBody closes body and propagates its error through *retErr only when *retErr is nil.
func closeBody(body io.ReadCloser, retErr *error) {
	if cerr := body.Close(); cerr != nil && *retErr == nil {
		*retErr = fmt.Errorf("closing permissions response body: %w", cerr)
	}
}

// decodePermissions unmarshals a subjectPermissionsResponse from r.
func decodePermissions(r io.Reader) ([]string, []string, error) {
	var result subjectPermissionsResponse
	if err := json.NewDecoder(r).Decode(&result); err != nil {
		return nil, nil, fmt.Errorf("decoding permissions response: %w", err)
	}
	return result.Roles, result.Permissions, nil
}

// GetSubjectPermissions fetches roles and permissions for subjectID.
// Returns empty slices (not an error) when the subject has no policy.
func (c *Client) GetSubjectPermissions(ctx context.Context, subjectID string) (_ []string, _ []string, retErr error) {
	rawURL, err := c.permissionsURL(subjectID)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating permissions request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("calling policy service: %w", err)
	}
	defer closeBody(resp.Body, &retErr)

	ok, err := permissionsStatusResult(resp.StatusCode, subjectID)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, nil
	}
	return decodePermissions(resp.Body)
}
