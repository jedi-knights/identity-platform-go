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
