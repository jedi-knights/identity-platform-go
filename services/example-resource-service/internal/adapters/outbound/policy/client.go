// Package policy implements ports.PolicyChecker by calling the
// authorization-policy-service POST /evaluate endpoint. This allows the
// resource service to enforce RBAC policies in addition to OAuth2 scope checks.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/ports"
)

// Compile-time interface check.
var _ ports.PolicyChecker = (*Client)(nil)

// Client calls the authorization-policy-service POST /evaluate endpoint.
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

type evaluateRequest struct {
	SubjectID string `json:"subject_id"`
	Resource  string `json:"resource"`
	Action    string `json:"action"`
}

type evaluateResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// Evaluate returns true if the policy service grants access.
// Infrastructure failures (non-200 responses, network errors) are returned as errors.
// A denied decision is expressed as (false, nil) — never as an error.
func (c *Client) Evaluate(ctx context.Context, subjectID, resource, action string) (_ bool, retErr error) {
	body, err := json.Marshal(evaluateRequest{SubjectID: subjectID, Resource: resource, Action: action})
	if err != nil {
		return false, fmt.Errorf("marshalling policy request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/evaluate", bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("creating policy request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("calling policy service: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil && retErr == nil {
			retErr = fmt.Errorf("closing policy response body: %w", err)
		}
	}()

	return parseEvaluateResponse(resp)
}

// parseEvaluateResponse checks the status code and decodes the evaluation result.
// Extracted from Evaluate to keep its cyclomatic complexity within bounds.
func parseEvaluateResponse(resp *http.Response) (bool, error) {
	if resp.StatusCode != http.StatusOK {
		return false, apperrors.New(apperrors.ErrCodeInternal, fmt.Sprintf("policy service returned %d", resp.StatusCode))
	}
	var result evaluateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("decoding policy response: %w", err)
	}
	return result.Allowed, nil
}
