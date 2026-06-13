package memory

import (
	"context"
	"sync"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// Compile-time interface check.
var _ domain.PasswordResetTokenRepository = (*PasswordResetTokenRepository)(nil)

// PasswordResetTokenRepository is an in-memory implementation of
// domain.PasswordResetTokenRepository.
type PasswordResetTokenRepository struct {
	mu     sync.RWMutex
	byHash map[string]*domain.PasswordResetToken
}

// NewPasswordResetTokenRepository returns an empty in-memory store.
func NewPasswordResetTokenRepository() *PasswordResetTokenRepository {
	return &PasswordResetTokenRepository{
		byHash: make(map[string]*domain.PasswordResetToken),
	}
}

func copyResetToken(t *domain.PasswordResetToken) *domain.PasswordResetToken {
	cp := *t
	return &cp
}

func (r *PasswordResetTokenRepository) Save(_ context.Context, token *domain.PasswordResetToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byHash[token.TokenHash]; exists {
		return apperrors.New(apperrors.ErrCodeConflict, "token already exists")
	}
	r.byHash[token.TokenHash] = copyResetToken(token)
	return nil
}

func (r *PasswordResetTokenRepository) FindByHash(_ context.Context, tokenHash string) (*domain.PasswordResetToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.byHash[tokenHash]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "token not found")
	}
	return copyResetToken(t), nil
}

func (r *PasswordResetTokenRepository) MarkUsed(_ context.Context, tokenHash string, usedAt time.Time) error {
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

func (r *PasswordResetTokenRepository) DeleteExpired(_ context.Context, before time.Time) (int64, error) {
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
