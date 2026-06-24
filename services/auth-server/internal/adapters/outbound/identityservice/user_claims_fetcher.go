package identityservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// Compile-time interface check — UserClaimsFetcher must satisfy the outbound
// port the ID-token issuer (ADR-0010) and /userinfo handler depend on.
var _ ports.UserClaimsFetcher = (*UserClaimsFetcher)(nil)

// claimsWireResponse mirrors identity-service's domain.UserClaims wire shape.
// updated_at is serialised as RFC 3339 by encoding/json on time.Time; we
// decode through *time.Time so a missing field deserialises as the zero
// time without erroring.
type claimsWireResponse struct {
	Subject       string     `json:"sub"`
	Email         string     `json:"email"`
	EmailVerified bool       `json:"email_verified"`
	Name          string     `json:"name"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
}

// UserClaimsFetcher implements ports.UserClaimsFetcher by calling
// identity-service GET /users/{id}/claims.
type UserClaimsFetcher struct {
	baseURL    string
	httpClient *http.Client
}

// NewUserClaimsFetcher returns a UserClaimsFetcher that calls the given
// identity-service base URL.
func NewUserClaimsFetcher(baseURL string, httpClient *http.Client) *UserClaimsFetcher {
	return &UserClaimsFetcher{baseURL: baseURL, httpClient: httpClient}
}

// GetUserClaims fetches the OIDC claim projection for subjectID. Returns
// apperrors.ErrCodeNotFound on a 404 from identity-service (so the caller
// can map it to {active:false} or 404 as appropriate). Other non-200
// statuses surface as ErrCodeInternal.
func (f *UserClaimsFetcher) GetUserClaims(ctx context.Context, subjectID string) (_ *ports.UserClaims, retErr error) {
	if subjectID == "" {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "subjectID is required")
	}
	url := fmt.Sprintf("%s/users/%s/claims", f.baseURL, subjectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "building user-claims request", err)
	}
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "fetching user claims", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing user-claims response", cerr)
		}
	}()
	if resp.StatusCode == http.StatusNotFound {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "user not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("user-claims: unexpected status " + resp.Status)
	}
	var body claimsWireResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "decoding user-claims response", err)
	}
	var updatedAt int64
	if body.UpdatedAt != nil {
		updatedAt = body.UpdatedAt.Unix()
	}
	return &ports.UserClaims{
		Subject:       body.Subject,
		Email:         body.Email,
		EmailVerified: body.EmailVerified,
		Name:          body.Name,
		UpdatedAt:     updatedAt,
	}, nil
}
