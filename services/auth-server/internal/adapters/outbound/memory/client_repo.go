package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// ClientRepository is an in-memory client repository.
type ClientRepository struct {
	mu      sync.RWMutex
	clients map[string]*domain.Client
}

func NewClientRepository(initial []*domain.Client) *ClientRepository {
	r := &ClientRepository{clients: make(map[string]*domain.Client)}
	for _, c := range initial {
		r.clients[c.ID] = c
	}
	return r
}

func (r *ClientRepository) FindByID(_ context.Context, id string) (*domain.Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	client, ok := r.clients[id]
	if !ok {
		return nil, fmt.Errorf("client not found: %s", id)
	}
	return client, nil
}

func (r *ClientRepository) Save(_ context.Context, client *domain.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[client.ID] = client
	return nil
}
