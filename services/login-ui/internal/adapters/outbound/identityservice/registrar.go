package identityservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// Compile-time check — drift between the adapter and the port surfaces
// at build time rather than at runtime.
var _ ports.UserRegistrar = (*Registrar)(nil)

// Registrar calls identity-service's /auth/register over HTTP. Shares
// no state with Authenticator — a single service can wire both as
// distinct ports even though they hit the same upstream.
type Registrar struct {
	baseURL    string
	httpClient *http.Client
}

// NewRegistrar returns a Registrar that posts to baseURL + /auth/register.
// httpClient must be non-nil; the composition root supplies a
// timeout-configured client.
func NewRegistrar(baseURL string, httpClient *http.Client) *Registrar {
	return &Registrar{baseURL: baseURL, httpClient: httpClient}
}

type registerBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// registerResponse mirrors identity-service's domain.RegisterResponse
// including the AccountID field E7-S1c added. omitempty on account_id
// means the JSON absence and empty string are both mapped to "".
type registerResponse struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	AccountID string `json:"account_id"`
}

// Register POSTs to identity-service and decodes the response. Nil-safe
// on AccountID — an upstream response with an absent or empty
// account_id is a valid success (deployments without
// IDENTITY_ENTITLEMENTS_SERVICE_URL emit that shape) and returns a
// RegisterResult with AccountID = "".
//
// Error mapping:
//   - 4xx from upstream -> ErrCodeBadRequest / ErrCodeConflict
//   - transport failure or any other status -> ErrCodeInternal
func (r *Registrar) Register(ctx context.Context, req ports.RegisterRequest) (_ *ports.RegisterResult, retErr error) {
	body, err := json.Marshal(registerBody(req))
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "marshalling register request", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+"/auth/register", bytes.NewReader(body))
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "building register request", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "identity-service unavailable", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing register response body", cerr)
		}
	}()
	return parseRegisterResponse(resp)
}

// parseRegisterResponse decodes the success body or maps the error
// status. Split out to keep Register within the project's
// cyclomatic-complexity budget.
func parseRegisterResponse(resp *http.Response) (*ports.RegisterResult, error) {
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		var rr registerResponse
		if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
			return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "decoding register response", err)
		}
		if rr.UserID == "" {
			return nil, apperrors.New(apperrors.ErrCodeInternal, "identity-service returned empty user_id")
		}
		return &ports.RegisterResult{
			UserID:    rr.UserID,
			Email:     rr.Email,
			Name:      rr.Name,
			AccountID: rr.AccountID, // "" when entitlements upstream unwired
		}, nil
	case http.StatusBadRequest:
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "invalid registration input")
	case http.StatusConflict:
		return nil, apperrors.New(apperrors.ErrCodeConflict, "email already registered")
	default:
		return nil, apperrors.New(apperrors.ErrCodeInternal, fmt.Sprintf("identity-service returned %d", resp.StatusCode))
	}
}
