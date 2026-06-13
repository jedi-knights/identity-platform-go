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

var _ domain.PasswordResetTokenRepository = (*PasswordResetTokenRepository)(nil)

// PasswordResetTokenRepository is a PostgreSQL-backed implementation of
// domain.PasswordResetTokenRepository.
type PasswordResetTokenRepository struct {
	pool *pgxpool.Pool
}

func NewPasswordResetTokenRepository(pool *pgxpool.Pool) *PasswordResetTokenRepository {
	return &PasswordResetTokenRepository{pool: pool}
}

func (r *PasswordResetTokenRepository) Save(ctx context.Context, token *domain.PasswordResetToken) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO password_reset_tokens (token_hash, user_id, expires_at, used_at, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		token.TokenHash, token.UserID, token.ExpiresAt, token.UsedAt, token.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return apperrors.New(apperrors.ErrCodeConflict, "token already exists")
		}
		return fmt.Errorf("saving password-reset token: %w", err)
	}
	return nil
}

func (r *PasswordResetTokenRepository) FindByHash(ctx context.Context, tokenHash string) (*domain.PasswordResetToken, error) {
	var t domain.PasswordResetToken
	err := r.pool.QueryRow(ctx,
		`SELECT token_hash, user_id, expires_at, used_at, created_at
		 FROM password_reset_tokens WHERE token_hash = $1`,
		tokenHash,
	).Scan(&t.TokenHash, &t.UserID, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "token not found")
	}
	if err != nil {
		return nil, fmt.Errorf("finding password-reset token: %w", err)
	}
	return &t, nil
}

func (r *PasswordResetTokenRepository) MarkUsed(ctx context.Context, tokenHash string, usedAt time.Time) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE password_reset_tokens SET used_at = $2 WHERE token_hash = $1`,
		tokenHash, usedAt,
	)
	if err != nil {
		return fmt.Errorf("marking password-reset token used: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return apperrors.New(apperrors.ErrCodeNotFound, "token not found")
	}
	return nil
}

func (r *PasswordResetTokenRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM password_reset_tokens WHERE expires_at < $1`,
		before,
	)
	if err != nil {
		return 0, fmt.Errorf("deleting expired password-reset tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}
