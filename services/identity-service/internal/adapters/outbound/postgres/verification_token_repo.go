package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// Compile-time interface check.
var _ domain.VerificationTokenRepository = (*VerificationTokenRepository)(nil)

// VerificationTokenRepository is a PostgreSQL-backed implementation of
// domain.VerificationTokenRepository.
type VerificationTokenRepository struct {
	pool *pgxpool.Pool
}

// NewVerificationTokenRepository constructs the repository.
func NewVerificationTokenRepository(pool *pgxpool.Pool) *VerificationTokenRepository {
	return &VerificationTokenRepository{pool: pool}
}

// Save persists a verification token. Hash collisions surface as
// ErrCodeConflict (vanishingly unlikely with SHA-256).
func (r *VerificationTokenRepository) Save(ctx context.Context, token *domain.VerificationToken) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO verification_tokens (token_hash, user_id, expires_at, used_at, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		token.TokenHash, token.UserID, token.ExpiresAt, token.UsedAt, token.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return apperrors.New(apperrors.ErrCodeConflict, "token already exists")
		}
		return fmt.Errorf("saving verification token: %w", err)
	}
	return nil
}

// FindByHash looks up a token by its SHA-256 hash.
func (r *VerificationTokenRepository) FindByHash(ctx context.Context, tokenHash string) (*domain.VerificationToken, error) {
	var t domain.VerificationToken
	err := r.pool.QueryRow(ctx,
		`SELECT token_hash, user_id, expires_at, used_at, created_at
		 FROM verification_tokens WHERE token_hash = $1`,
		tokenHash,
	).Scan(&t.TokenHash, &t.UserID, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "token not found")
	}
	if err != nil {
		return nil, fmt.Errorf("finding verification token: %w", err)
	}
	return &t, nil
}

// MarkUsed atomically sets used_at on the token.
func (r *VerificationTokenRepository) MarkUsed(ctx context.Context, tokenHash string, usedAt time.Time) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE verification_tokens SET used_at = $2 WHERE token_hash = $1`,
		tokenHash, usedAt,
	)
	if err != nil {
		return fmt.Errorf("marking token used: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return apperrors.New(apperrors.ErrCodeNotFound, "token not found")
	}
	return nil
}

// DeleteExpired removes tokens whose expires_at is before the given threshold.
// Returns the number of rows deleted.
func (r *VerificationTokenRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM verification_tokens WHERE expires_at < $1`,
		before,
	)
	if err != nil {
		return 0, fmt.Errorf("deleting expired tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}
