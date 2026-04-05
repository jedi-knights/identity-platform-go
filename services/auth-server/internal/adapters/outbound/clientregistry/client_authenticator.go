// Package clientregistry implements the auth-server's outbound ports by delegating
// to client-registry-service over HTTP. This is the production adapter; the in-memory
// adapter in adapters/outbound/memory is used for local development without the full stack.
package clientregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// validateRequest is the payload for POST /clients/validate.
type validateRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// validateResponse is the response from POST /clients/validate.
type validateResponse struct {
	Valid bool `json:"valid"`
}

// getClientResponse mirrors client-registry-service's domain.GetClientResponse.
type getClientResponse struct {
	ClientID     string   `json:"client_id"`
	Name         string   `json:"name"`
	Scopes       []string `json:"scopes"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Active       bool     `json:"active"`
}

// ClientAuthenticator implements ports.ClientAuthenticator by calling
// client-registry-service. Credential validation and metadata retrieval
// are two separate calls so that the client secret is never returned over the wire.
type ClientAuthenticator struct {
	baseURL    string
	httpClient *http.Client
}

// NewClientAuthenticator returns a ClientAuthenticator that calls the given base URL.
func NewClientAuthenticator(baseURL string, httpClient *http.Client) *ClientAuthenticator {
	return &ClientAuthenticator{baseURL: baseURL, httpClient: httpClient}
}

// Authenticate validates credentials via POST /clients/validate, then fetches metadata
// via GET /clients/{id}. Returns apperrors.ErrCodeUnauthorized if credentials are invalid.
func (a *ClientAuthenticator) Authenticate(ctx context.Context, clientID, clientSecret string) (*domain.Client, error) {
	if err := a.validate(ctx, clientID, clientSecret); err != nil {
		return nil, err
	}
	return a.getClient(ctx, clientID)
}

func (a *ClientAuthenticator) validate(ctx context.Context, clientID, clientSecret string) (retErr error) {
	body, err := json.Marshal(validateRequest{ClientID: clientID, ClientSecret: clientSecret})
	if err != nil {
		return apperrors.Wrap(apperrors.ErrCodeInternal, "marshalling validate request", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/clients/validate", bytes.NewReader(body))
	if err != nil {
		return apperrors.Wrap(apperrors.ErrCodeInternal, "building validate request", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrCodeInternal, "client-registry-service unavailable", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing validate response body", err)
		}
	}()

	return parseValidateResponse(resp)
}

// parseValidateResponse checks the status code and returns an error when the
// credentials are rejected. Extracted from validate to keep its cyclomatic
// complexity within bounds.
//
// The contract with client-registry-service is:
//   - 200 OK → credentials accepted
//   - 401 Unauthorized → credentials rejected (known rejection, not a server failure)
//   - anything else → infrastructure error
//
// For backward compatibility with older versions of client-registry-service that
// return 200 with {"valid":false}, the response body is also checked when the
// status is 200.
func parseValidateResponse(resp *http.Response) error {
	if resp.StatusCode == http.StatusUnauthorized {
		return apperrors.New(apperrors.ErrCodeUnauthorized, "client authentication failed")
	}
	if resp.StatusCode != http.StatusOK {
		return apperrors.New(apperrors.ErrCodeInternal, fmt.Sprintf("client-registry-service returned %d", resp.StatusCode))
	}
	var result validateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return apperrors.Wrap(apperrors.ErrCodeInternal, "decoding validate response", err)
	}
	if !result.Valid {
		return apperrors.New(apperrors.ErrCodeUnauthorized, "client authentication failed")
	}
	return nil
}

func (a *ClientAuthenticator) getClient(ctx context.Context, clientID string) (_ *domain.Client, retErr error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/clients/"+clientID, nil)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "building get-client request", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "client-registry-service unavailable", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing get-client response body", err)
		}
	}()

	return parseClientResponse(resp)
}

// parseClientResponse checks the status code, decodes the client metadata, and
// maps it to a domain.Client. Extracted from getClient to keep its cyclomatic
// complexity within bounds.
func parseClientResponse(resp *http.Response) (*domain.Client, error) {
	if resp.StatusCode == http.StatusNotFound {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "client not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, apperrors.New(apperrors.ErrCodeInternal, fmt.Sprintf("client-registry-service returned %d", resp.StatusCode))
	}
	var cr getClientResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "decoding client response", err)
	}
	return toClient(&cr), nil
}

// toClient maps a client-registry response to auth-server's domain.Client.
// The Secret field is intentionally empty: credentials were already validated
// by the validate call; the domain.Client here carries only metadata.
func toClient(cr *getClientResponse) *domain.Client {
	grantTypes := make([]domain.GrantType, len(cr.GrantTypes))
	for i, gt := range cr.GrantTypes {
		grantTypes[i] = domain.GrantType(gt)
	}
	return &domain.Client{
		ID:           cr.ClientID,
		Name:         cr.Name,
		Scopes:       cr.Scopes,
		RedirectURIs: cr.RedirectURIs,
		GrantTypes:   grantTypes,
	}
}
