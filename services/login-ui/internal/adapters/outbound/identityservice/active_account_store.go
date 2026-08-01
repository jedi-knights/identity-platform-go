package identityservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// Compile-time interface check — build fails if the port drifts.
var _ ports.ActiveAccountStore = (*ActiveAccountStore)(nil)

// activeAccountWireResponse mirrors identity-service's
// activeAccountResponse. account_id is a pointer on the wire so
// "never set" arrives as JSON null; the store projects that to "".
type activeAccountWireResponse struct {
	AccountID *string `json:"account_id"`
}

type setActiveAccountWireRequest struct {
	AccountID string `json:"account_id"`
}

// ActiveAccountStore reads and writes the user's active-account
// preference against identity-service /users/{id}/active-account
// (E7-S3a). Wired at composition time via LOGIN_UI_IDENTITY_SERVICE_URL
// — the same URL the credential authenticator uses.
type ActiveAccountStore struct {
	baseURL    string
	httpClient *http.Client
}

// NewActiveAccountStore constructs an ActiveAccountStore. baseURL must
// NOT include the /users/... path; the adapter appends it.
func NewActiveAccountStore(baseURL string, httpClient *http.Client) *ActiveAccountStore {
	return &ActiveAccountStore{baseURL: baseURL, httpClient: httpClient}
}

// GetActiveAccount fetches the currently-selected account for userID.
// Returns "" (nil error) when identity-service reports the user has
// not chosen. Non-2xx statuses surface as ErrCodeInternal.
func (s *ActiveAccountStore) GetActiveAccount(ctx context.Context, userID string) (_ string, retErr error) {
	if userID == "" {
		return "", apperrors.New(apperrors.ErrCodeBadRequest, "userID is required")
	}
	resp, err := s.doGetActiveAccount(ctx, userID)
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing get-active-account response", cerr)
		}
	}()
	return decodeActiveAccountResponse(resp)
}

// doGetActiveAccount builds and executes the GET request, returning the
// response only when StatusCode == 200. Callers must close the body.
func (s *ActiveAccountStore) doGetActiveAccount(ctx context.Context, userID string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/users/%s/active-account", s.baseURL, userID), nil)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "building get-active-account request", err)
	}
	req.Header.Set("X-Requester-User-ID", userID)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "fetching active account", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, errors.New("get-active-account: unexpected status " + resp.Status)
	}
	return resp, nil
}

// decodeActiveAccountResponse projects the wire body to an accountID.
// JSON null on the wire projects to "".
func decodeActiveAccountResponse(resp *http.Response) (string, error) {
	var body activeAccountWireResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "decoding get-active-account response", err)
	}
	if body.AccountID == nil {
		return "", nil
	}
	return *body.AccountID, nil
}

// SetActiveAccount PUTs the user's active-account choice. accountID
// must be non-empty. A 204 response is the happy path; anything else
// surfaces as ErrCodeInternal.
func (s *ActiveAccountStore) SetActiveAccount(ctx context.Context, userID, accountID string) (retErr error) {
	if userID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "userID is required")
	}
	if accountID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "accountID is required")
	}
	resp, err := s.doSetActiveAccount(ctx, userID, accountID)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing set-active-account response", cerr)
		}
	}()
	if resp.StatusCode != http.StatusNoContent {
		return errors.New("set-active-account: unexpected status " + resp.Status)
	}
	return nil
}

// doSetActiveAccount builds and executes the PUT request. Callers own
// the response body and its close.
func (s *ActiveAccountStore) doSetActiveAccount(ctx context.Context, userID, accountID string) (*http.Response, error) {
	payload, err := json.Marshal(setActiveAccountWireRequest{AccountID: accountID})
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "encoding set-active-account request", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		fmt.Sprintf("%s/users/%s/active-account", s.baseURL, userID), bytes.NewReader(payload))
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "building set-active-account request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requester-User-ID", userID)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "sending set-active-account request", err)
	}
	return resp, nil
}
