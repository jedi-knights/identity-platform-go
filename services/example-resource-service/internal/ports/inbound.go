package ports

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/domain"
)

// ResourceLister lists all resources.
type ResourceLister interface {
	ListResources(ctx context.Context) ([]*domain.Resource, error)
}

// ResourceGetter gets a resource by ID.
type ResourceGetter interface {
	GetResource(ctx context.Context, id string) (*domain.Resource, error)
}

// ResourceCreator creates a new resource.
type ResourceCreator interface {
	CreateResource(ctx context.Context, req application.CreateResourceRequest) (*domain.Resource, error)
}
