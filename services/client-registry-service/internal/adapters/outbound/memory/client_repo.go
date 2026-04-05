package memory

import (
	"context"
	"sync"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

// Compile-time interface check.
var _ domain.ClientRepository = (*ClientRepository)(nil)

// ClientRepository is an in-memory implementation of domain.ClientRepository.
type ClientRepository struct {
	mu      sync.RWMutex
	clients map[string]*domain.OAuthClient
}

// NewClientRepository creates an empty in-memory client repository.
func NewClientRepository() *ClientRepository {
	return &ClientRepository{
		clients: make(map[string]*domain.OAuthClient),
	}
}

// copyClient returns a deep copy of c. The struct-level fields are copied by value,
// and each slice field (Scopes, RedirectURIs, GrantTypes) gets its own backing array
// so mutations to the copy cannot corrupt the stored entry and vice-versa.
func copyClient(c *domain.OAuthClient) *domain.OAuthClient {
	copied := *c
	copied.Scopes = append([]string(nil), c.Scopes...)
	copied.RedirectURIs = append([]string(nil), c.RedirectURIs...)
	copied.GrantTypes = append([]string(nil), c.GrantTypes...)
	return &copied
}

// FindByID returns the client with the given ID, or ErrCodeNotFound if absent.
// The returned value is a deep copy; mutations do not affect the stored entry.
func (r *ClientRepository) FindByID(_ context.Context, id string) (*domain.OAuthClient, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clients[id]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "client not found")
	}
	// Return a deep copy so callers cannot mutate the stored value through the pointer.
	return copyClient(c), nil
}

// Save persists a new client. Returns ErrCodeConflict if a client with the same ID already exists.
// A deep copy of the provided value is stored; subsequent mutations by the caller are not reflected.
func (r *ClientRepository) Save(_ context.Context, client *domain.OAuthClient) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.clients[client.ID]; exists {
		return apperrors.New(apperrors.ErrCodeConflict, "client already exists")
	}
	// Store a deep copy so post-call mutations by the caller cannot corrupt the store.
	r.clients[client.ID] = copyClient(client)
	return nil
}

// Update replaces a stored client with the provided value. Returns ErrCodeNotFound if absent.
// A deep copy of the provided value is stored; subsequent mutations by the caller are not reflected.
func (r *ClientRepository) Update(_ context.Context, client *domain.OAuthClient) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.clients[client.ID]; !ok {
		return apperrors.New(apperrors.ErrCodeNotFound, "client not found")
	}
	// Store a deep copy so post-call mutations by the caller cannot corrupt the store.
	r.clients[client.ID] = copyClient(client)
	return nil
}

// Delete removes the client with the given ID. Returns ErrCodeNotFound if absent.
func (r *ClientRepository) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.clients[id]; !ok {
		return apperrors.New(apperrors.ErrCodeNotFound, "client not found")
	}
	delete(r.clients, id)
	return nil
}

// List returns deep copies of all stored clients. The returned slice is never nil.
func (r *ClientRepository) List(_ context.Context) ([]*domain.OAuthClient, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*domain.OAuthClient, 0, len(r.clients))
	for _, c := range r.clients {
		// Return deep copies so callers cannot mutate stored values through the pointers.
		result = append(result, copyClient(c))
	}
	return result, nil
}
