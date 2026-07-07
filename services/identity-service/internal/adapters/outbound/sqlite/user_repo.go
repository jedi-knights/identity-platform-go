package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// Unlike the postgres adapter (which relies on a server-side `now()`
// column default and never reads timestamps back onto the struct), this
// adapter writes exactly the CreatedAt/UpdatedAt values already present on
// the domain.User the caller passed in — matching the in-memory adapter's
// behavior, which is the "reference" fallback every other adapter is
// swapped in for. Callers (see application/auth_service.go) already set
// these fields before calling Save/Update.

// Compile-time interface check — ensures UserRepository always satisfies domain.UserRepository.
var _ domain.UserRepository = (*UserRepository)(nil)

// UserRepository is a SQLite-backed implementation of domain.UserRepository.
// Safe for concurrent use; *sql.DB manages its own connection pool.
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a UserRepository backed by the given database
// handle. The handle must already be open; call Connect to obtain one.
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

// FindByID retrieves a user by their unique ID.
// Returns an ErrCodeNotFound AppError when no such user exists.
func (r *UserRepository) FindByID(ctx context.Context, id string) (*domain.User, error) {
	return r.findOne(ctx, `SELECT id, email, name, password_hash, active, created_at, updated_at, email_verified_at
		FROM users WHERE id = ?`, id)
}

// FindByEmail retrieves a user by their email address.
// Returns an ErrCodeNotFound AppError when no such user exists.
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	return r.findOne(ctx, `SELECT id, email, name, password_hash, active, created_at, updated_at, email_verified_at
		FROM users WHERE email = ?`, email)
}

// findOne runs query with a single arg and scans the result into a User.
// Extracted from FindByID/FindByEmail to avoid duplicating the scan and
// NULL-handling logic.
func (r *UserRepository) findOne(ctx context.Context, query, arg string) (*domain.User, error) {
	var u domain.User
	var createdAt, updatedAt string
	var emailVerifiedAt sql.NullString
	err := r.db.QueryRowContext(ctx, query, arg).Scan(
		&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.Active, &createdAt, &updatedAt, &emailVerifiedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("finding user: %w", err)
	}
	if u.CreatedAt, err = textToTime(createdAt); err != nil {
		return nil, fmt.Errorf("parsing created_at for user %q: %w", u.ID, err)
	}
	if u.UpdatedAt, err = textToTime(updatedAt); err != nil {
		return nil, fmt.Errorf("parsing updated_at for user %q: %w", u.ID, err)
	}
	if u.EmailVerifiedAt, err = textToNullTime(emailVerifiedAt); err != nil {
		return nil, fmt.Errorf("parsing email_verified_at for user %q: %w", u.ID, err)
	}
	return &u, nil
}

// Save persists a new user record. It returns an ErrCodeConflict AppError if the
// email is already registered.
func (r *UserRepository) Save(ctx context.Context, user *domain.User) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users (id, email, name, password_hash, active, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Email, user.Name, user.PasswordHash, user.Active,
		timeToText(user.CreatedAt), timeToText(user.UpdatedAt),
	)
	if isUniqueViolation(err) {
		return apperrors.New(apperrors.ErrCodeConflict, "email already registered")
	}
	if err != nil {
		return fmt.Errorf("saving user: %w", err)
	}
	return nil
}

// Update replaces a user's mutable fields, including UpdatedAt exactly as
// set on the passed-in struct. Returns an ErrCodeNotFound AppError when no
// row with the given ID exists.
func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	tag, err := r.db.ExecContext(ctx,
		`UPDATE users
		 SET email = ?, name = ?, password_hash = ?, active = ?, updated_at = ?
		 WHERE id = ?`,
		user.Email, user.Name, user.PasswordHash, user.Active, timeToText(user.UpdatedAt), user.ID,
	)
	if isUniqueViolation(err) {
		return apperrors.New(apperrors.ErrCodeConflict, "email already registered")
	}
	if err != nil {
		return fmt.Errorf("updating user: %w", err)
	}
	rows, err := tag.RowsAffected()
	if err != nil {
		return fmt.Errorf("reading rows affected for user %q: %w", user.ID, err)
	}
	if rows == 0 {
		return apperrors.New(apperrors.ErrCodeNotFound, "user not found")
	}
	return nil
}

// MarkEmailVerified atomically sets email_verified_at on the user, using
// verifiedAt as both the verification timestamp and the new updated_at —
// avoiding a second, separately-generated wall-clock read inside the adapter.
// Returns ErrCodeNotFound if no row with the given ID exists.
func (r *UserRepository) MarkEmailVerified(ctx context.Context, userID string, verifiedAt time.Time) error {
	tag, err := r.db.ExecContext(ctx,
		`UPDATE users SET email_verified_at = ?, updated_at = ? WHERE id = ?`,
		timeToText(verifiedAt), timeToText(verifiedAt), userID,
	)
	if err != nil {
		return fmt.Errorf("marking email verified: %w", err)
	}
	rows, err := tag.RowsAffected()
	if err != nil {
		return fmt.Errorf("reading rows affected for user %q: %w", userID, err)
	}
	if rows == 0 {
		return apperrors.New(apperrors.ErrCodeNotFound, "user not found")
	}
	return nil
}
