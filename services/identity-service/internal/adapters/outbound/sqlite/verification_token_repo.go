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

// Compile-time interface check.
var _ domain.VerificationTokenRepository = (*VerificationTokenRepository)(nil)

// VerificationTokenRepository is a SQLite-backed implementation of
// domain.VerificationTokenRepository.
type VerificationTokenRepository struct {
	db *sql.DB
}

// NewVerificationTokenRepository constructs the repository.
func NewVerificationTokenRepository(db *sql.DB) *VerificationTokenRepository {
	return &VerificationTokenRepository{db: db}
}

// Save persists a verification token. Hash collisions surface as
// ErrCodeConflict (vanishingly unlikely with SHA-256).
func (r *VerificationTokenRepository) Save(ctx context.Context, token *domain.VerificationToken) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO verification_tokens (token_hash, user_id, expires_at, used_at, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		token.TokenHash, token.UserID, timeToText(token.ExpiresAt), nullTimeToText(token.UsedAt), timeToText(token.CreatedAt),
	)
	if isUniqueViolation(err) {
		return apperrors.New(apperrors.ErrCodeConflict, "token already exists")
	}
	if err != nil {
		return fmt.Errorf("saving verification token: %w", err)
	}
	return nil
}

// FindByHash looks up a token by its SHA-256 hash.
func (r *VerificationTokenRepository) FindByHash(ctx context.Context, tokenHash string) (*domain.VerificationToken, error) {
	var t domain.VerificationToken
	var expiresAt, createdAt string
	var usedAt sql.NullString
	err := r.db.QueryRowContext(ctx,
		`SELECT token_hash, user_id, expires_at, used_at, created_at
		 FROM verification_tokens WHERE token_hash = ?`,
		tokenHash,
	).Scan(&t.TokenHash, &t.UserID, &expiresAt, &usedAt, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "token not found")
	}
	if err != nil {
		return nil, fmt.Errorf("finding verification token: %w", err)
	}
	if t.ExpiresAt, err = textToTime(expiresAt); err != nil {
		return nil, fmt.Errorf("parsing expires_at for token: %w", err)
	}
	if t.CreatedAt, err = textToTime(createdAt); err != nil {
		return nil, fmt.Errorf("parsing created_at for token: %w", err)
	}
	if t.UsedAt, err = textToNullTime(usedAt); err != nil {
		return nil, fmt.Errorf("parsing used_at for token: %w", err)
	}
	return &t, nil
}

// MarkUsed atomically sets used_at on the token.
func (r *VerificationTokenRepository) MarkUsed(ctx context.Context, tokenHash string, usedAt time.Time) error {
	tag, err := r.db.ExecContext(ctx,
		`UPDATE verification_tokens SET used_at = ? WHERE token_hash = ?`,
		timeToText(usedAt), tokenHash,
	)
	if err != nil {
		return fmt.Errorf("marking token used: %w", err)
	}
	rows, err := tag.RowsAffected()
	if err != nil {
		return fmt.Errorf("reading rows affected for token: %w", err)
	}
	if rows == 0 {
		return apperrors.New(apperrors.ErrCodeNotFound, "token not found")
	}
	return nil
}

// DeleteExpired removes tokens whose expires_at is before the given threshold.
// Returns the number of rows deleted.
func (r *VerificationTokenRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	tag, err := r.db.ExecContext(ctx,
		`DELETE FROM verification_tokens WHERE expires_at < ?`,
		timeToText(before),
	)
	if err != nil {
		return 0, fmt.Errorf("deleting expired tokens: %w", err)
	}
	return tag.RowsAffected()
}
