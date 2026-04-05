package domain

import (
	"context"
	"time"
)

// Resource is an example protected resource.
type Resource struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	OwnerID     string    `json:"owner_id"`
	CreatedAt   time.Time `json:"created_at"`
}

// ResourceRepository defines persistence for resources.
type ResourceRepository interface {
	FindByID(ctx context.Context, id string) (*Resource, error)
	FindAll(ctx context.Context) ([]*Resource, error)
	Save(ctx context.Context, resource *Resource) error
}

// CreateResourceRequest holds input for creating a resource.
type CreateResourceRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	OwnerID     string `json:"owner_id"`
}
