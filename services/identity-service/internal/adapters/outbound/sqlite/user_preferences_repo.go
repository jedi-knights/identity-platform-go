package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// Compile-time interface check.
var _ domain.UserPreferencesRepository = (*UserPreferencesRepository)(nil)

// UserPreferencesRepository is a SQLite-backed implementation of
// domain.UserPreferencesRepository.
type UserPreferencesRepository struct {
	db *sql.DB
}

// NewUserPreferencesRepository constructs the repository.
func NewUserPreferencesRepository(db *sql.DB) *UserPreferencesRepository {
	return &UserPreferencesRepository{db: db}
}

// Get returns the preferences row for userID, or (nil, nil) when none exists.
func (r *UserPreferencesRepository) Get(ctx context.Context, userID string) (*domain.UserPreferences, error) {
	var (
		prefs           domain.UserPreferences
		activeAccountID sql.NullString
		updatedAt       string
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT user_id, active_account_id, updated_at
		 FROM user_preferences WHERE user_id = ?`,
		userID,
	).Scan(&prefs.UserID, &activeAccountID, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fetching user preferences: %w", err)
	}
	if activeAccountID.Valid {
		prefs.ActiveAccountID = activeAccountID.String
	}
	parsed, err := textToTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing updated_at: %w", err)
	}
	prefs.UpdatedAt = parsed
	return &prefs, nil
}

// SetActiveAccount upserts the ActiveAccountID for userID. SQLite's
// INSERT ... ON CONFLICT DO UPDATE is atomic within a single statement,
// so concurrent writers cannot lose an update to interleaving.
func (r *UserPreferencesRepository) SetActiveAccount(ctx context.Context, userID, accountID string, now time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO user_preferences (user_id, active_account_id, updated_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT (user_id) DO UPDATE
		 SET active_account_id = excluded.active_account_id,
		     updated_at        = excluded.updated_at`,
		userID, accountID, timeToText(now),
	)
	if err != nil {
		return fmt.Errorf("upserting user preferences: %w", err)
	}
	return nil
}
