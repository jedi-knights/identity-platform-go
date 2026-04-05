package memory

import (
	"context"
	"sync"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

// ClientRepository is an in-memory implementation of domain.ClientRepository.
type ClientRepository struct {
	mu      sync.RWMutex
	clients map[string]*domain.OAuthClient
}

func NewClientRepository() *ClientRepository {
	return &ClientRepository{
		clients: make(map[string]*domain.OAuthClient),
	}
}

func (r *ClientRepository) FindByID(_ context.Context, id string) (*domain.OAuthClient, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clients[id]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "client not found")
	}
	return c, nil
}

func (r *ClientRepository) Save(_ context.Context, client *domain.OAuthClient) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[client.ID] = client
	return nil
}

func (r *ClientRepository) Update(_ context.Context, client *domain.OAuthClient) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.clients[client.ID]; !ok {
		return apperrors.New(apperrors.ErrCodeNotFound, "client not found")
	}
	r.clients[client.ID] = client
	return nil
}

func (r *ClientRepository) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.clients[id]; !ok {
		return apperrors.New(apperrors.ErrCodeNotFound, "client not found")
	}
	delete(r.clients, id)
	return nil
}

func (r *ClientRepository) List(_ context.Context) ([]*domain.OAuthClient, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*domain.OAuthClient, 0, len(r.clients))
	for _, c := range r.clients {
		result = append(result, c)
	}
	return result, nil
}
