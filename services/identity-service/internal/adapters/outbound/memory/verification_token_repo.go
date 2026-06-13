package memory

import (
	"context"
	"sync"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// Compile-time interface check.
var _ domain.VerificationTokenRepository = (*VerificationTokenRepository)(nil)

// VerificationTokenRepository is an in-memory implementation of
// domain.VerificationTokenRepository. Suitable for tests and the
// zero-dependency dev fallback; not for production.
type VerificationTokenRepository struct {
	mu     sync.RWMutex
	byHash map[string]*domain.VerificationToken
}

// NewVerificationTokenRepository returns an empty in-memory store.
func NewVerificationTokenRepository() *VerificationTokenRepository {
	return &VerificationTokenRepository{
		byHash: make(map[string]*domain.VerificationToken),
	}
}

func copyToken(t *domain.VerificationToken) *domain.VerificationToken {
	cp := *t
	return &cp
}

// Save persists a new token. Hash collisions are rejected as ErrCodeConflict
// — effectively impossible with SHA-256.
func (r *VerificationTokenRepository) Save(_ context.Context, token *domain.VerificationToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byHash[token.TokenHash]; exists {
		return apperrors.New(apperrors.ErrCodeConflict, "token already exists")
	}
	r.byHash[token.TokenHash] = copyToken(token)
	return nil
}

// FindByHash returns the token with the given SHA-256 hash, or ErrCodeNotFound
// if absent.
func (r *VerificationTokenRepository) FindByHash(_ context.Context, tokenHash string) (*domain.VerificationToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.byHash[tokenHash]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "token not found")
	}
	return copyToken(t), nil
}

// MarkUsed sets UsedAt on the stored token.
func (r *VerificationTokenRepository) MarkUsed(_ context.Context, tokenHash string, usedAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.byHash[tokenHash]
	if !ok {
		return apperrors.New(apperrors.ErrCodeNotFound, "token not found")
	}
	stamp := usedAt
	t.UsedAt = &stamp
	return nil
}

// DeleteExpired removes tokens whose ExpiresAt is before `before`. Returns
// the number of rows deleted.
func (r *VerificationTokenRepository) DeleteExpired(_ context.Context, before time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for hash, t := range r.byHash {
		if t.ExpiresAt.Before(before) {
			delete(r.byHash, hash)
			n++
		}
	}
	return n, nil
}
