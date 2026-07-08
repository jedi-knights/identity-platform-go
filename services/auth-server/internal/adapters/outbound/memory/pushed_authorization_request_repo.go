package memory

import (
	"context"
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// Compile-time interface check — fails at build time if
// PushedAuthorizationRequestRepository drifts from the domain interface.
// Marks the swap point for the Redis adapter (ADR-0005 / ADR-0021).
var _ domain.PushedAuthorizationRequestRepository = (*PushedAuthorizationRequestRepository)(nil)

// PushedAuthorizationRequestRepository is an in-memory store for RFC 9126
// pushed authorization requests. Not safe for multi-replica deployments —
// each replica holds an independent copy. Production deployments use the
// Redis adapter; this exists for local development without the full stack.
type PushedAuthorizationRequestRepository struct {
	mu       sync.Mutex
	requests map[string]*domain.PushedAuthorizationRequest // keyed by RequestURI
}

// NewPushedAuthorizationRequestRepository creates an empty store.
func NewPushedAuthorizationRequestRepository() *PushedAuthorizationRequestRepository {
	return &PushedAuthorizationRequestRepository{requests: make(map[string]*domain.PushedAuthorizationRequest)}
}

// Save persists the request. Re-Save under the same RequestURI key
// overwrites the prior record, mirroring the authorization-code store's
// SET semantics.
func (r *PushedAuthorizationRequestRepository) Save(_ context.Context, req *domain.PushedAuthorizationRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests[req.RequestURI] = req
	return nil
}

// Consume atomically reads and deletes the request identified by
// requestURI. The single mutex held across the lookup and the delete is
// what makes the operation atomic, exactly like AuthorizationCodeRepository.
func (r *PushedAuthorizationRequestRepository) Consume(_ context.Context, requestURI string) (*domain.PushedAuthorizationRequest, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	req, ok := r.requests[requestURI]
	if !ok {
		return nil, domain.ErrPushedAuthorizationRequestNotFound
	}
	delete(r.requests, requestURI)
	if req.IsExpiredAt(time.Now()) {
		return nil, domain.ErrPushedAuthorizationRequestNotFound
	}
	return req, nil
}
