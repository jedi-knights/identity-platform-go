package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/ports"
)

var _ ports.InviteRepository = (*InviteRepository)(nil)

// InviteRepository is the Postgres-backed InviteRepository. Uses the
// same pool as AccountRepository — the container passes it in.
type InviteRepository struct {
	pool *pgxpool.Pool
}

// NewInviteRepository constructs an InviteRepository backed by pool.
func NewInviteRepository(pool *pgxpool.Pool) *InviteRepository {
	return &InviteRepository{pool: pool}
}

// Insert persists inv. Enforces the no-open-duplicate invariant via
// the accounts_no_dup_open_idx partial unique index — a duplicate
// insert raises a unique-violation which the adapter maps to
// ErrCodeConflict.
func (r *InviteRepository) Insert(ctx context.Context, inv domain.Invite) (*domain.Invite, error) {
	const q = `
		INSERT INTO account_invites
			(account_id, invited_by_seat_id, invited_email, token_hash, expires_at, accepted_at, revoked_at)
		VALUES
			($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, account_id, invited_by_seat_id, invited_email, token_hash,
		          expires_at, accepted_at, revoked_at, created_at`
	out := &domain.Invite{}
	err := r.pool.QueryRow(ctx, q,
		inv.AccountID, inv.InvitedBySeatID, inv.InvitedEmail, inv.TokenHash,
		inv.ExpiresAt, inv.AcceptedAt, inv.RevokedAt,
	).Scan(
		&out.ID, &out.AccountID, &out.InvitedBySeatID, &out.InvitedEmail, &out.TokenHash,
		&out.ExpiresAt, &out.AcceptedAt, &out.RevokedAt, &out.CreatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, apperrors.New(apperrors.ErrCodeConflict,
				"an open invite for this email already exists on the account")
		}
		return nil, fmt.Errorf("insert invite: %w", err)
	}
	// Preserve caller-supplied RawToken — not persisted, but returned
	// so the application layer can hand it to the email adapter.
	out.RawToken = inv.RawToken
	return out, nil
}

// CountOpen counts pending invites (not accepted, not revoked, not
// past expiry) for accountID. Uses the partial index
// account_invites_pending_by_account_idx for the scan; the expiry
// predicate is added in the WHERE clause since the index does not
// include expires_at.
func (r *InviteRepository) CountOpen(ctx context.Context, accountID string) (int, error) {
	const q = `
		SELECT COUNT(*)
		FROM account_invites
		WHERE account_id = $1
		  AND accepted_at IS NULL
		  AND revoked_at IS NULL
		  AND expires_at > now()`
	var n int
	if err := r.pool.QueryRow(ctx, q, accountID).Scan(&n); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("count open invites: %w", err)
	}
	return n, nil
}
