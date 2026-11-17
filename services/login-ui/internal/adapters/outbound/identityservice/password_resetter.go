package identityservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// Compile-time check — drift between the adapter and the port surfaces at
// build time rather than at runtime.
var _ ports.PasswordResetter = (*PasswordResetter)(nil)

// maxDrainBytes bounds how much of an upstream response body is read before
// the connection is reused or closed; the bodies here are ignored.
const maxDrainBytes = 1 << 20

// PasswordResetter calls identity-service's password-reset endpoints over
// HTTP. Like Registrar it shares no state with the other adapters that hit
// the same upstream.
type PasswordResetter struct {
	baseURL    string
	httpClient *http.Client
}

// NewPasswordResetter returns a PasswordResetter targeting baseURL.
// httpClient must be non-nil; the composition root supplies a
// timeout-configured client.
func NewPasswordResetter(baseURL string, httpClient *http.Client) *PasswordResetter {
	return &PasswordResetter{baseURL: baseURL, httpClient: httpClient}
}

// RequestReset asks identity-service to email a reset link. Upstream answers
// 204 whether or not the address is registered, so success carries no
// information about the account.
func (p *PasswordResetter) RequestReset(ctx context.Context, email string) error {
	return p.post(ctx, "/auth/request-password-reset", map[string]string{"email": email}, "", http.StatusNoContent)
}

// ResetPassword redeems a reset token and sets the new password. clientIP, when
// non-empty, is sent as X-Forwarded-For so identity-service can key its redeem
// rate limit on the end user (it honors the header only from trusted peers).
func (p *PasswordResetter) ResetPassword(ctx context.Context, token, newPassword, clientIP string) error {
	return p.post(ctx, "/auth/reset-password", map[string]string{"token": token, "new_password": newPassword}, clientIP, http.StatusOK)
}

// post sends body as JSON and maps the upstream status to an apperrors
// category. wantStatus is the one success status for the endpoint. Error
// messages never include the request body: it carries a token and password.
func (p *PasswordResetter) post(ctx context.Context, path string, body any, clientIP string, wantStatus int) (retErr error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrCodeInternal, "marshalling password-reset request", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return apperrors.Wrap(apperrors.ErrCodeInternal, "building password-reset request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if clientIP != "" {
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrCodeInternal, "identity-service unavailable", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes)) // best-effort drain so the connection can be reused
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing password-reset response body", cerr)
		}
	}()
	return mapPasswordResetStatus(resp.StatusCode, wantStatus)
}

// mapPasswordResetStatus converts an upstream status into an apperrors
// category, or nil when it is the expected success status.
func mapPasswordResetStatus(status, want int) error {
	switch status {
	case want:
		return nil
	case http.StatusBadRequest:
		return apperrors.New(apperrors.ErrCodeBadRequest, "invalid password-reset input")
	case http.StatusUnauthorized:
		return apperrors.New(apperrors.ErrCodeUnauthorized, "invalid or expired reset token")
	case http.StatusTooManyRequests:
		return apperrors.New(apperrors.ErrCodeRateLimit, "password-reset rate limit exceeded")
	default:
		return apperrors.New(apperrors.ErrCodeInternal, fmt.Sprintf("identity-service returned %d", status))
	}
}
