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
