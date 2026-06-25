// Package ports defines the inbound and outbound port interfaces for the auth-server.
// Outbound repository interfaces (ClientRepository, TokenRepository) live in the domain
// package per the hexagonal architecture rule: domain has no outward dependencies.
// Service-to-service outbound ports live here.
package ports

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// ClientAuthenticator is the outbound port for authenticating an OAuth2 client.
//
// It combines credential validation and metadata retrieval in one call so that
// implementations can delegate both to client-registry-service over HTTP without
// exposing the client secret over the wire. The in-memory implementation wraps
// domain.ClientRepository and performs the comparison locally.
type ClientAuthenticator interface {
	// Authenticate validates the client credentials and returns the client's metadata.
	// Returns apperrors.ErrCodeUnauthorized if the credentials are invalid or the client
	// does not exist. Returns apperrors.ErrCodeInternal on infrastructure failure.
	Authenticate(ctx context.Context, clientID, clientSecret string) (*domain.Client, error)
}

// ClientLookup is the outbound port for fetching client metadata without
// presenting a credential. /oauth/authorize uses it because the user-agent
// holds no secret at that stage; the handler still needs RedirectURIs and
// Scopes to validate the request before storing a LoginChallenge.
//
// Returns apperrors.ErrCodeNotFound when the client does not exist;
// apperrors.ErrCodeInternal on infrastructure failure.
type ClientLookup interface {
	Lookup(ctx context.Context, clientID string) (*domain.Client, error)
}

// UserAuthenticator is the outbound port for verifying end-user credentials against
// the identity-service. It is used by the authorization_code grant to authenticate
// the resource owner before issuing an authorization code.
type UserAuthenticator interface {
	// VerifyCredentials checks the user's email and password.
	// Returns the user's ID on success.
	// Returns apperrors.ErrCodeUnauthorized if the credentials are invalid.
	// Returns apperrors.ErrCodeInternal on infrastructure failure.
	VerifyCredentials(ctx context.Context, email, password string) (userID string, err error)
}

// SubjectPermissionsFetcher retrieves the resolved RBAC permissions for a subject
// from the authorization-policy-service at token issuance time.
// When nil, tokens are issued without roles/permissions claims.
type SubjectPermissionsFetcher interface {
	GetSubjectPermissions(ctx context.Context, subjectID string) (roles []string, permissions []string, err error)
}

// UserClaims is the auth-server-side projection of identity-service's user
// claims response. Field shape mirrors OIDC Core §5.1 standard claim names;
// auth-server selects which fields to copy into the issued ID token (and
// the /userinfo response) based on the access token's scope set.
type UserClaims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	UpdatedAt     int64 // Unix seconds
}

// UserClaimsFetcher is the outbound port for retrieving the identity claims
// auth-server's ID-token issuer and /userinfo endpoint use to populate
// profile and email information. Backed by identity-service's
// GET /users/{id}/claims projection (ADR-0010).
//
// When the auth-server is run without AUTH_IDENTITY_SERVICE_URL the
// implementation is nil — issuance falls back to omitting profile claims,
// and /userinfo returns the platform's minimum (sub only).
type UserClaimsFetcher interface {
	GetUserClaims(ctx context.Context, subjectID string) (*UserClaims, error)
}
