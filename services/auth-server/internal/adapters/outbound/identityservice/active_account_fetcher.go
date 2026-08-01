package identityservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// Compile-time interface check — ActiveAccountFetcher must satisfy the
// outbound port the token strategies depend on for E7-S3c claim wiring.
var _ ports.ActiveAccountFetcher = (*ActiveAccountFetcher)(nil)

// activeAccountWireResponse mirrors identity-service's
// activeAccountResponse (services/identity-service internal/adapters/
// inbound/http/user_preferences_handler.go). The identity-service
// contract is "account_id is a pointer so 'never set' serialises as
// JSON null" — decoding into *string preserves the distinction so the
// fetcher can emit "" (never chosen) vs a real ID unambiguously.
type activeAccountWireResponse struct {
	AccountID *string `json:"account_id"`
}

// ActiveAccountFetcher implements ports.ActiveAccountFetcher by calling
// identity-service GET /users/{id}/active-account. Uses the shared
// identity-service base URL — the same one UserClaimsFetcher points at,
// wired at composition time via AUTH_IDENTITY_SERVICE_URL.
type ActiveAccountFetcher struct {
	baseURL    string
	httpClient *http.Client
}

// NewActiveAccountFetcher returns an ActiveAccountFetcher that calls
// the given identity-service base URL.
func NewActiveAccountFetcher(baseURL string, httpClient *http.Client) *ActiveAccountFetcher {
	return &ActiveAccountFetcher{baseURL: baseURL, httpClient: httpClient}
}

// GetActiveAccount fetches the currently-selected account for userID.
// Returns "" (nil error) when identity-service reports the user has
// never chosen; returns "" plus an apperror on any transport / status
// failure so the caller can log-and-continue without conflating "no
// selection" with "service down".
//
// The interim RBAC bridge on identity-service (E7-S3a) requires the
// X-Requester-User-ID header to match the path {id}. Auth-server sends
// the header set to userID — auth-server is trusted infrastructure
// speaking to identity-service on the user's behalf.
func (f *ActiveAccountFetcher) GetActiveAccount(ctx context.Context, userID string) (_ string, retErr error) {
	if userID == "" {
		return "", apperrors.New(apperrors.ErrCodeBadRequest, "userID is required")
	}
	resp, err := f.doGetActiveAccount(ctx, userID)
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing active-account response", cerr)
		}
	}()
	return decodeActiveAccountResponse(resp)
}

// doGetActiveAccount issues the GET and surfaces transport / status
// errors. Returns the response only when StatusCode == 200; callers
// must close the body.
func (f *ActiveAccountFetcher) doGetActiveAccount(ctx context.Context, userID string) (*http.Response, error) {
	url := fmt.Sprintf("%s/users/%s/active-account", f.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "building active-account request", err)
	}
	// Interim RBAC bridge (E7-S3a): identity-service requires this
	// header to equal the path {id}. Replaced with a validated JWT
	// claim once auth-server's own token integration into identity-
	// service lands.
	req.Header.Set("X-Requester-User-ID", userID)
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "fetching active account", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, errors.New("active-account: unexpected status " + resp.Status)
	}
	return resp, nil
}

// decodeActiveAccountResponse decodes the JSON body into a plain
// accountID string. A nil AccountID (JSON null) becomes "" — the
// caller's omitempty behaviour drops the claim from the issued token.
func decodeActiveAccountResponse(resp *http.Response) (string, error) {
	var body activeAccountWireResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "decoding active-account response", err)
	}
	if body.AccountID == nil {
		return "", nil
	}
	return *body.AccountID, nil
}
