package memory

import (
	"context"
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// Compile-time interface check — fails at build time if AuthorizationCodeRepository
// drifts from the domain interface. Marks the swap point for the Redis adapter
// (ADR-0005 / ADR-0009).
var _ domain.AuthorizationCodeRepository = (*AuthorizationCodeRepository)(nil)

// AuthorizationCodeRepository is an in-memory store for OAuth 2.1 authorization
// codes. Not safe for multi-replica deployments — each replica holds an
// independent copy. Production deployments use the Redis adapter; this exists
// for local development without the full stack.
type AuthorizationCodeRepository struct {
	mu    sync.Mutex
	codes map[string]*domain.AuthorizationCode // keyed by Code
}

// NewAuthorizationCodeRepository creates an empty store.
func NewAuthorizationCodeRepository() *AuthorizationCodeRepository {
	return &AuthorizationCodeRepository{codes: make(map[string]*domain.AuthorizationCode)}
}

// Save persists the code. Re-Save under the same Code key overwrites the
// prior record — this matches the Redis adapter's SET semantics and lets a
// callers retry without first calling Delete.
func (r *AuthorizationCodeRepository) Save(_ context.Context, code *domain.AuthorizationCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.codes[code.Code] = code
	return nil
}

// Consume atomically reads and deletes the code identified by raw. The
// single mutex held across the lookup and the delete is what makes the
// operation atomic — concurrent callers serialize on the lock, exactly one
// reads the value, the rest see ErrAuthorizationCodeNotFound.
//
// Expired codes are treated as not found (and deleted on observation) so
// the store does not retain entries past their useful life.
func (r *AuthorizationCodeRepository) Consume(_ context.Context, raw string) (*domain.AuthorizationCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	code, ok := r.codes[raw]
	if !ok {
		return nil, domain.ErrAuthorizationCodeNotFound
	}
	delete(r.codes, raw)
	if code.IsExpiredAt(time.Now()) {
		return nil, domain.ErrAuthorizationCodeNotFound
	}
	return code, nil
}
