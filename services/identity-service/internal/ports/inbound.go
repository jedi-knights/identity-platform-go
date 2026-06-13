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
