package memory

import (
	"context"
	"sync"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// Compile-time interface check — fails at build time if RefreshTokenRepository drifts
// from the domain.RefreshTokenRepository interface. This marks the swap point for scaling
// beyond a single replica (see ADR-0005).
var _ domain.RefreshTokenRepository = (*RefreshTokenRepository)(nil)

// RefreshTokenRepository is an in-memory RefreshTokenRepository for local development.
// Not safe for multi-replica deployments — each replica holds an independent copy of
// its data; see ADR-0005 and the horizontal scalability constraints in CLAUDE.md.
type RefreshTokenRepository struct {
	mu     sync.RWMutex
	tokens map[string]*domain.RefreshToken // keyed by Raw
}

// NewRefreshTokenRepository creates an empty in-memory RefreshTokenRepository.
func NewRefreshTokenRepository() *RefreshTokenRepository {
	return &RefreshTokenRepository{tokens: make(map[string]*domain.RefreshToken)}
}

// Save stores the refresh token keyed by its Raw value.
func (r *RefreshTokenRepository) Save(_ context.Context, token *domain.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens[token.Raw] = token
	return nil
}

// FindByRaw retrieves a refresh token by its raw value.
// Returns domain.ErrRefreshTokenNotFound when not present.
func (r *RefreshTokenRepository) FindByRaw(_ context.Context, raw string) (*domain.RefreshToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if t, ok := r.tokens[raw]; ok {
		return t, nil
	}
	return nil, domain.ErrRefreshTokenNotFound
}

// Delete removes a refresh token. Returns domain.ErrRefreshTokenNotFound when not present.
func (r *RefreshTokenRepository) Delete(_ context.Context, raw string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.tokens[raw]; !ok {
		return domain.ErrRefreshTokenNotFound
	}
	delete(r.tokens, raw)
	return nil
}
