// Package ports declares the outbound service interfaces login-ui depends
// on. Implementations live under internal/adapters/outbound/<service>.
// Following the hexagonal architecture rule (ADR-0001), the handler depends
// on these interfaces — never on a concrete HTTP client.
package ports

import "context"

// UserAuthenticator verifies end-user credentials against identity-service.
// On success the returned subjectID is the canonical user identifier the
// authorization-code grant will stamp onto the issued token's `sub` claim.
//
// Implementations return apperrors.ErrCodeUnauthorized for bad credentials
// and apperrors.ErrCodeInternal on infrastructure failure; login-ui surfaces
// the first as "invalid email or password" and renders a generic message
// for the second.
type UserAuthenticator interface {
	VerifyCredentials(ctx context.Context, email, password string) (subjectID string, err error)
}

// IssueCodeRequest captures the inputs login-ui sends to auth-server's
// /internal/issue-code endpoint after a successful sign-in and consent.
// ConsentGranted carries the scopes the user approved — it must be a
// subset of the scopes recorded on the login challenge.
type IssueCodeRequest struct {
	LoginChallenge string
	SessionID      string
	ConsentGranted []string
}

// IssueCodeResponse is the auth-server response to /internal/issue-code.
// RedirectURI and State come straight from the stored LoginChallenge — the
// handler never reads them from the form body, so a tampered POST cannot
// reach an unregistered URL.
type IssueCodeResponse struct {
	Code        string
	RedirectURI string
	State       string
}

// AuthCodeIssuer is the outbound port behind auth-server's
// /internal/issue-code endpoint. Implementations attach the shared service
// bearer token and decode the JSON response into IssueCodeResponse.
type AuthCodeIssuer interface {
	IssueCode(ctx context.Context, req IssueCodeRequest) (*IssueCodeResponse, error)
}
