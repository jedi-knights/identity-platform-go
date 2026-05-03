// Package introspection implements ports.TokenIntrospector by calling
// token-introspection-service over HTTP. This ensures that token revocation
// performed via auth-server is honoured by the resource service.
package introspection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/ports"
)

type introspectResponse struct {
	Active      bool     `json:"active"`
	Subject     string   `json:"sub"`
	ClientID    string   `json:"client_id"`
	Scope       string   `json:"scope"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// Client implements ports.TokenIntrospector by calling token-introspection-service.
type Client struct {
	baseURL    string
	httpClient *http.Client
	secret     string
}

// NewClient returns a Client that calls the given base URL.
// secret is sent as Authorization: Bearer <secret> when non-empty, satisfying the
// token-introspection-service's caller authentication requirement (RFC 7662 §2.1).
// Pass "" to make unauthenticated requests (local dev without INTROSPECT_SECRET_KEY).
func NewClient(baseURL string, httpClient *http.Client, secret string) *Client {
	return &Client{baseURL: baseURL, httpClient: httpClient, secret: secret}
}

// buildIntrospectRequest constructs the POST /introspect request with the appropriate headers.
func (c *Client) buildIntrospectRequest(ctx context.Context, raw string) (*http.Request, error) {
	body := strings.NewReader(url.Values{"token": {raw}}.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/introspect", body)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "building introspect request", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	return req, nil
}

// Introspect calls POST /introspect on token-introspection-service.
// Infrastructure failures are returned as errors; token invalidity is expressed
// as Active=false (RFC 7662 §2.2).
func (c *Client) Introspect(ctx context.Context, raw string) (_ *ports.IntrospectionResult, retErr error) {
	req, err := c.buildIntrospectRequest(ctx, raw)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "token-introspection-service unavailable", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing introspect response body", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		// Drain the body (bounded) so the HTTP transport can reuse the underlying connection.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, apperrors.New(apperrors.ErrCodeInternal, fmt.Sprintf("token-introspection-service returned %d", resp.StatusCode))
	}

	var ir introspectResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ir); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "decoding introspect response", err)
	}

	return &ports.IntrospectionResult{
		Active:      ir.Active,
		Subject:     ir.Subject,
		ClientID:    ir.ClientID,
		Scope:       ir.Scope,
		Roles:       ir.Roles,
		Permissions: ir.Permissions,
	}, nil
}
