package ports

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

// ClientCreator is the inbound port for creating OAuth clients.
type ClientCreator interface {
	CreateClient(ctx context.Context, req domain.CreateClientRequest) (*domain.CreateClientResponse, error)
}

// ClientReader is the inbound port for reading OAuth client data.
type ClientReader interface {
	GetClient(ctx context.Context, id string) (*domain.GetClientResponse, error)
	ListClients(ctx context.Context) ([]*domain.GetClientResponse, error)
}

// ClientValidator is the inbound port for validating client credentials.
type ClientValidator interface {
	ValidateClient(ctx context.Context, req domain.ValidateClientRequest) (*domain.ValidateClientResponse, error)
}

// ClientDeleter is the inbound port for removing OAuth clients.
type ClientDeleter interface {
	DeleteClient(ctx context.Context, id string) error
}

// ClientRegistrar is the inbound port for RFC 7591 dynamic client
// registration. Separate from [ClientCreator] because the request /
// response shapes and the error vocabulary differ — RFC 7591 owns its
// own codes (invalid_redirect_uri, invalid_client_metadata,
// invalid_software_statement) and they do not pass through apperrors.
type ClientRegistrar interface {
	Register(ctx context.Context, req domain.RegistrationRequest) (*domain.RegistrationResponse, error)
}

// ClientRegistrationManager is the inbound port for the RFC 7592
// management endpoints. Every method takes the bearer token from the
// Authorization header so the application layer can bcrypt-compare
// against the stored hash; the HTTP layer does not authenticate, it
// only extracts and forwards.
type ClientRegistrationManager interface {
	ReadRegistration(ctx context.Context, clientID, token string) (*domain.RegistrationResponse, error)
	UpdateRegistration(ctx context.Context, clientID, token string, req domain.RegistrationRequest) (*domain.RegistrationResponse, error)
	DeleteRegistration(ctx context.Context, clientID, token string) error
}
