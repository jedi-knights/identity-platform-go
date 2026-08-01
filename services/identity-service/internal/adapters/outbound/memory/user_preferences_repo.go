package memory

import (
	"context"
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// Compile-time interface check.
var _ domain.UserPreferencesRepository = (*UserPreferencesRepository)(nil)

// UserPreferencesRepository is an in-memory implementation of
// domain.UserPreferencesRepository. Safe for concurrent use.
//
// The memory adapter does not enforce the postgres FK to users(id) — that
// check is out of scope for a dependency-free in-memory harness. Tests
// that need the FK behavior use the postgres or sqlite adapter.
type UserPreferencesRepository struct {
	mu   sync.RWMutex
	rows map[string]*domain.UserPreferences
}

// NewUserPreferencesRepository returns an empty in-memory
// UserPreferencesRepository.
func NewUserPreferencesRepository() *UserPreferencesRepository {
	return &UserPreferencesRepository{
		rows: make(map[string]*domain.UserPreferences),
	}
}

func copyUserPreferences(p *domain.UserPreferences) *domain.UserPreferences {
	cp := *p
	return &cp
}

// Get returns the preferences row for userID, or (nil, nil) when none exists.
func (r *UserPreferencesRepository) Get(_ context.Context, userID string) (*domain.UserPreferences, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	row, ok := r.rows[userID]
	if !ok {
		return nil, nil
	}
	return copyUserPreferences(row), nil
}

// SetActiveAccount upserts the ActiveAccountID for userID.
func (r *UserPreferencesRepository) SetActiveAccount(_ context.Context, userID, accountID string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[userID] = &domain.UserPreferences{
		UserID:          userID,
		ActiveAccountID: accountID,
		UpdatedAt:       now,
	}
	return nil
}
