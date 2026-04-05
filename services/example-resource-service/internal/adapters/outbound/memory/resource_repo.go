package memory

import (
	"context"
	"sync"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/domain"
)

// ResourceRepository is an in-memory ResourceRepository implementation.
type ResourceRepository struct {
	mu        sync.RWMutex
	resources map[string]*domain.Resource
}

// NewResourceRepository creates a ResourceRepository seeded with a default resource.
func NewResourceRepository() *ResourceRepository {
	r := &ResourceRepository{
		resources: make(map[string]*domain.Resource),
	}
	// Seed directly to avoid the overhead of locking through Save.
	r.resources["res-1"] = &domain.Resource{
		ID:          "res-1",
		Name:        "Sample Resource",
		Description: "A sample protected resource",
		OwnerID:     "user-1",
		CreatedAt:   time.Now(),
	}
	return r
}

// FindByID returns the resource with the given ID, or ErrCodeNotFound.
func (r *ResourceRepository) FindByID(_ context.Context, id string) (*domain.Resource, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res, ok := r.resources[id]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "resource not found")
	}
	return res, nil
}

// FindAll returns all stored resources.
func (r *ResourceRepository) FindAll(_ context.Context) ([]*domain.Resource, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*domain.Resource, 0, len(r.resources))
	for _, res := range r.resources {
		result = append(result, res)
	}
	return result, nil
}

// Save persists the resource, overwriting any existing entry for the same ID.
func (r *ResourceRepository) Save(_ context.Context, resource *domain.Resource) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resources[resource.ID] = resource
	return nil
}
