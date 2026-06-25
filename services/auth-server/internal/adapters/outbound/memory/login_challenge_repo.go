package memory

import (
	"context"
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// Compile-time interface check — fails at build time if the adapter drifts
// from the domain port. The blank-identifier pattern matches every other
// memory adapter in this service.
var _ domain.LoginChallengeRepository = (*LoginChallengeRepository)(nil)

// LoginChallengeRepository is an in-memory store for /oauth/authorize
// state (ADR-0011). Not safe for multi-replica deployments — each replica
// holds an independent copy. Local-dev only; production uses the Redis
// adapter.
type LoginChallengeRepository struct {
	mu         sync.Mutex
	challenges map[string]*domain.LoginChallenge // keyed by ID
}

// NewLoginChallengeRepository returns an empty store.
func NewLoginChallengeRepository() *LoginChallengeRepository {
	return &LoginChallengeRepository{challenges: make(map[string]*domain.LoginChallenge)}
}

// Save persists the challenge. Re-Save under the same ID overwrites — this
// matches the Redis SET semantics and avoids forcing the caller to
// delete-then-save.
func (r *LoginChallengeRepository) Save(_ context.Context, c *domain.LoginChallenge) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.challenges[c.ID] = c
	return nil
}

// Get returns the challenge without removing it. Expired entries are
// treated as not present (and the record is dropped on observation) so the
// store never grows unbounded under heavy authorize traffic.
func (r *LoginChallengeRepository) Get(_ context.Context, id string) (*domain.LoginChallenge, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.challenges[id]
	if !ok {
		return nil, domain.ErrLoginChallengeNotFound
	}
	if c.IsExpiredAt(time.Now()) {
		delete(r.challenges, id)
		return nil, domain.ErrLoginChallengeNotFound
	}
	return c, nil
}

// Update overwrites the stored record for ID. Returns ErrLoginChallengeNotFound
// when the ID does not exist — Update is meant for adding consent / session
// data to an in-flight challenge, not for creating one.
func (r *LoginChallengeRepository) Update(_ context.Context, c *domain.LoginChallenge) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.challenges[c.ID]; !ok {
		return domain.ErrLoginChallengeNotFound
	}
	r.challenges[c.ID] = c
	return nil
}

// Consume atomically reads and deletes the challenge identified by ID. The
// mutex held across the lookup and delete is what makes the operation
// atomic — concurrent /internal/issue-code calls serialise on the lock,
// exactly one reads the value, the rest see ErrLoginChallengeNotFound.
func (r *LoginChallengeRepository) Consume(_ context.Context, id string) (*domain.LoginChallenge, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.challenges[id]
	if !ok {
		return nil, domain.ErrLoginChallengeNotFound
	}
	delete(r.challenges, id)
	if c.IsExpiredAt(time.Now()) {
		return nil, domain.ErrLoginChallengeNotFound
	}
	return c, nil
}
