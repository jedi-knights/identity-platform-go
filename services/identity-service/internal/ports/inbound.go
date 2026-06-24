package ports

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// Authenticator is the inbound port for user authentication.
type Authenticator interface {
	Login(ctx context.Context, req domain.LoginRequest) (*domain.LoginResponse, error)
}

// UserRegistrar is the inbound port for user registration.
type UserRegistrar interface {
	Register(ctx context.Context, req domain.RegisterRequest) (*domain.RegisterResponse, error)
}

// EmailVerifier is the inbound port for the email-verification flow.
// The flow has two halves: the user requests a verification email
// (RequestVerification) and later redeems the token it contained (VerifyEmail).
type EmailVerifier interface {
	// RequestVerification sends a verification email to the user matching the
	// request. The response intentionally contains no information about
	// whether the email is on file — callers must not be able to enumerate
	// users via this endpoint.
	RequestVerification(ctx context.Context, req domain.RequestVerificationRequest) error

	// VerifyEmail redeems a token and marks the user's email as verified.
	// Returns ErrCodeBadRequest for missing tokens, ErrCodeUnauthorized for
	// unknown / expired / already-used tokens.
	VerifyEmail(ctx context.Context, req domain.VerifyEmailRequest) (*domain.VerifyEmailResponse, error)
}

// UserClaimsProvider is the inbound port behind GET /users/{id}/claims —
// the projection ADR-0010's /userinfo endpoint on auth-server consumes to
// fill the OIDC profile/email claims into its response.
//
// This service does NOT understand the OIDC scope vocabulary — it returns
// the full claim set every time and lets auth-server filter by what the
// access token's scopes permit. Keeping the scope-aware filtering at
// auth-server's edge means identity-service stays OAuth-protocol-agnostic
// (the boundary in identity-service/CLAUDE.md).
type UserClaimsProvider interface {
	GetUserClaims(ctx context.Context, userID string) (*domain.UserClaims, error)
}
