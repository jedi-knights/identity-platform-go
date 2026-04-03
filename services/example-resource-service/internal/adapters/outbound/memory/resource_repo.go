package memory

import (
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

func NewResourceRepository() *ResourceRepository {
	r := &ResourceRepository{
		resources: make(map[string]*domain.Resource),
	}
	_ = r.Save(&domain.Resource{
		ID:          "res-1",
		Name:        "Sample Resource",
		Description: "A sample protected resource",
		OwnerID:     "user-1",
		CreatedAt:   time.Now(),
	})
	return r
}

func (r *ResourceRepository) FindByID(id string) (*domain.Resource, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res, ok := r.resources[id]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "resource not found")
	}
	return res, nil
}

func (r *ResourceRepository) FindAll() ([]*domain.Resource, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*domain.Resource, 0, len(r.resources))
	for _, res := range r.resources {
		result = append(result, res)
	}
	return result, nil
}

func (r *ResourceRepository) Save(resource *domain.Resource) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resources[resource.ID] = resource
	return nil
}
