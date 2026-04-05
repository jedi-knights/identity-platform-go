package memory

import (
	"context"
	"sync"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// Compile-time interface check.
var _ domain.UserRepository = (*UserRepository)(nil)

// UserRepository is an in-memory implementation of domain.UserRepository.
// It is safe for concurrent use.
type UserRepository struct {
	mu      sync.RWMutex
	byID    map[string]*domain.User
	byEmail map[string]*domain.User
}

// NewUserRepository returns an empty in-memory UserRepository.
func NewUserRepository() *UserRepository {
	return &UserRepository{
		byID:    make(map[string]*domain.User),
		byEmail: make(map[string]*domain.User),
	}
}

// copyUser returns a shallow copy of u, preventing pointer aliasing between
// stored state and values held by callers. Safe because domain.User contains
// only value types (string, bool, time.Time).
func copyUser(u *domain.User) *domain.User {
	cp := *u
	return &cp
}

// FindByID returns the user with the given ID, or ErrCodeNotFound if absent.
func (r *UserRepository) FindByID(_ context.Context, id string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.byID[id]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "user not found")
	}
	return copyUser(u), nil
}

// FindByEmail returns the user with the given email, or ErrCodeNotFound if absent.
func (r *UserRepository) FindByEmail(_ context.Context, email string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.byEmail[email]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "user not found")
	}
	return copyUser(u), nil
}

// Save persists a new user. Returns ErrCodeConflict if the email is already registered.
func (r *UserRepository) Save(_ context.Context, user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byEmail[user.Email]; exists {
		return apperrors.New(apperrors.ErrCodeConflict, "email already registered")
	}
	cp := copyUser(user)
	r.byID[user.ID] = cp
	r.byEmail[user.Email] = cp
	return nil
}

// Update replaces a user's stored fields. Returns ErrCodeNotFound if no user with
// the given ID exists.
func (r *UserRepository) Update(_ context.Context, user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	old, ok := r.byID[user.ID]
	if !ok {
		return apperrors.New(apperrors.ErrCodeNotFound, "user not found")
	}
	// Remove stale email index entry if email changed.
	if old.Email != user.Email {
		delete(r.byEmail, old.Email)
	}
	cp := copyUser(user)
	r.byID[user.ID] = cp
	r.byEmail[user.Email] = cp
	return nil
}
