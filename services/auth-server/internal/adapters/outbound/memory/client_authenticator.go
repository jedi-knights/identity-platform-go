package memory

import (
	"context"
	"crypto/subtle"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// ClientAuthenticator is the in-memory implementation of ports.ClientAuthenticator.
// It wraps ClientRepository and performs constant-time secret comparison locally.
//
// To scale horizontally, implement ports.ClientAuthenticator in a new package
// (e.g., adapters/outbound/clientregistry) and wire it in container.go.
// No changes to domain or application are required.
var _ interface {
	Authenticate(ctx context.Context, clientID, clientSecret string) (*domain.Client, error)
} = (*ClientAuthenticator)(nil)

// ClientAuthenticator validates client credentials against the in-memory store.
type ClientAuthenticator struct {
	repo *ClientRepository
}

// NewClientAuthenticator returns a ClientAuthenticator backed by the given repository.
func NewClientAuthenticator(repo *ClientRepository) *ClientAuthenticator {
	return &ClientAuthenticator{repo: repo}
}

// Authenticate validates credentials and returns the client's metadata.
// Uses constant-time comparison to prevent timing attacks.
func (a *ClientAuthenticator) Authenticate(ctx context.Context, clientID, clientSecret string) (*domain.Client, error) {
	client, err := a.repo.FindByID(ctx, clientID)
	if err != nil {
		return nil, apperrors.New(apperrors.ErrCodeUnauthorized, "client authentication failed")
	}
	if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) != 1 {
		return nil, apperrors.New(apperrors.ErrCodeUnauthorized, "client authentication failed")
	}
	return client, nil
}
