package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// Compile-time interface check.
var _ domain.UserPreferencesRepository = (*UserPreferencesRepository)(nil)

// UserPreferencesRepository is a PostgreSQL-backed implementation of
// domain.UserPreferencesRepository. Safe for concurrent use — pgxpool
// manages its own connection pool.
type UserPreferencesRepository struct {
	pool *pgxpool.Pool
}

// NewUserPreferencesRepository creates a UserPreferencesRepository backed
// by the given connection pool. The pool must already be open and healthy.
func NewUserPreferencesRepository(pool *pgxpool.Pool) *UserPreferencesRepository {
	return &UserPreferencesRepository{pool: pool}
}

// Get returns the preferences row for userID, or (nil, nil) when no row
// exists (the user has never set a preference). A missing users row is
// indistinguishable from a missing preferences row at this layer — both
// return (nil, nil). Callers that need to distinguish should probe the
// users table separately.
func (r *UserPreferencesRepository) Get(ctx context.Context, userID string) (*domain.UserPreferences, error) {
	var (
		prefs           domain.UserPreferences
		activeAccountID *string
	)
	err := r.pool.QueryRow(ctx,
		`SELECT user_id, active_account_id, updated_at
		 FROM user_preferences WHERE user_id = $1`,
		userID,
	).Scan(&prefs.UserID, &activeAccountID, &prefs.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fetching user preferences: %w", err)
	}
	if activeAccountID != nil {
		prefs.ActiveAccountID = *activeAccountID
	}
	return &prefs, nil
}

// SetActiveAccount upserts the ActiveAccountID for userID. INSERT ... ON
// CONFLICT (user_id) DO UPDATE runs atomically in a single statement,
// so concurrent writers cannot lose an update to interleaving.
func (r *UserPreferencesRepository) SetActiveAccount(ctx context.Context, userID, accountID string, now time.Time) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO user_preferences (user_id, active_account_id, updated_at)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_id) DO UPDATE
		 SET active_account_id = EXCLUDED.active_account_id,
		     updated_at        = EXCLUDED.updated_at`,
		userID, accountID, now,
	)
	if err != nil {
		return fmt.Errorf("upserting user preferences: %w", err)
	}
	return nil
}
