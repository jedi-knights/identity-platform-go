// Package postgres provides a PostgreSQL-backed implementation of the
// entitlements-service outbound ports. Uses pgx/v5 for database access
// and golang-migrate for schema migrations. Migration files are
// embedded at compile time so the binary is self-contained.
package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	pgxmigrate "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/ports"
)

//go:embed migrations
var migrationsFS embed.FS

// Compile-time interface checks — mark the swap points from the memory
// adapter and catch drift at declaration site.
var (
	_ ports.AccountRepository = (*AccountRepository)(nil)
	_ ports.SeatRepository    = (*AccountRepository)(nil)
)

// AccountRepository is the Postgres-backed AccountRepository +
// SeatRepository. Safe for concurrent use — pgxpool manages its own
// connection pool.
type AccountRepository struct {
	pool *pgxpool.Pool
}

// NewAccountRepository constructs an AccountRepository backed by pool.
// pool must already be open and healthy — call Connect to obtain one.
func NewAccountRepository(pool *pgxpool.Pool) *AccountRepository {
	return &AccountRepository{pool: pool}
}

// Connect opens a pooled Postgres connection and verifies reachability
// with a ping. Caller owns the returned pool and must Close it on
// shutdown.
func Connect(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("opening postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}
	return pool, nil
}

// RunMigrations applies all pending schema migrations embedded in the
// binary. Idempotent — safe to call at every startup.
func RunMigrations(databaseURL string) error {
	d, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("creating migration source: %w", err)
	}
	cfg, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return fmt.Errorf("parsing database URL: %w", err)
	}
	db := stdlib.OpenDB(*cfg)
	defer func() { _ = db.Close() }()
	driver, err := pgxmigrate.WithInstance(db, &pgxmigrate.Config{})
	if err != nil {
		return fmt.Errorf("creating migrate driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", d, "pgx5", driver)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("running migrations: %w", err)
	}
	return nil
}

// UpsertPersonalAccount creates a personal account for userID or returns
// the existing one. Uses ON CONFLICT (user_id) on the accounts_user_id_
// unique_idx partial index to make the create idempotent under
// concurrent stampede. Wraps account + owner-seat in a single
// transaction so the two rows land together or not at all.
func (r *AccountRepository) UpsertPersonalAccount(ctx context.Context, userID, email string) (*domain.Account, error) {
	if err := validateUpsertInput(userID, email); err != nil {
		return nil, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	acc, created, err := upsertAccountRow(ctx, tx, userID, email)
	if err != nil {
		return nil, err
	}
	if created {
		if err := insertOwnerSeat(ctx, tx, acc.ID, userID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return acc, nil
}

// validateUpsertInput enforces the wire-boundary shape rules so
// UpsertPersonalAccount stays under the gocyclo budget.
func validateUpsertInput(userID, email string) error {
	if userID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "user_id is required")
	}
	if email == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "email is required")
	}
	return nil
}

// upsertAccountRow performs the account upsert. Returns created=true
// only when this call inserted the row; on the conflict path it looks
// up and returns the existing row without a second round-trip beyond
// the ON CONFLICT DO NOTHING probe.
func upsertAccountRow(ctx context.Context, tx pgx.Tx, userID, email string) (*domain.Account, bool, error) {
	const insert = `
		INSERT INTO accounts (display_name, billing_email, user_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) WHERE user_id IS NOT NULL DO NOTHING
		RETURNING id, display_name, billing_email, user_id,
		          COALESCE(lago_customer_id, ''), created_at, updated_at`
	acc := &domain.Account{}
	err := tx.QueryRow(ctx, insert, email, email, userID).Scan(
		&acc.ID, &acc.DisplayName, &acc.BillingEmail, &acc.UserID,
		&acc.LagoCustomerID, &acc.CreatedAt, &acc.UpdatedAt,
	)
	if err == nil {
		return acc, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fmt.Errorf("insert account: %w", err)
	}
	// Conflict path — read the existing row.
	const sel = `
		SELECT id, display_name, billing_email, user_id,
		       COALESCE(lago_customer_id, ''), created_at, updated_at
		FROM accounts WHERE user_id = $1`
	err = tx.QueryRow(ctx, sel, userID).Scan(
		&acc.ID, &acc.DisplayName, &acc.BillingEmail, &acc.UserID,
		&acc.LagoCustomerID, &acc.CreatedAt, &acc.UpdatedAt,
	)
	if err != nil {
		return nil, false, fmt.Errorf("read existing account after conflict: %w", err)
	}
	return acc, false, nil
}

// insertOwnerSeat inserts the owner Seat row for a freshly-created
// account. Fires only on the create path; the ON CONFLICT clause is a
// belt-and-braces guard against the theoretical race where two
// transactions both see the account as new (should not happen given
// the upsert above, but the schema enforces it either way).
func insertOwnerSeat(ctx context.Context, tx pgx.Tx, accountID, userID string) error {
	const q = `
		INSERT INTO account_seats (account_id, user_id, role)
		VALUES ($1, $2, 'owner')
		ON CONFLICT (account_id, user_id) DO NOTHING`
	if _, err := tx.Exec(ctx, q, accountID, userID); err != nil {
		// pgconn.PgError is imported to make future error-code inspection
		// (e.g. distinguishing constraint violations) idiomatic.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return fmt.Errorf("insert owner seat (%s): %w", pgErr.Code, err)
		}
		return fmt.Errorf("insert owner seat: %w", err)
	}
	return nil
}

// FindByUserID returns the personal account owned by userID or a
// not-found error when none exists.
func (r *AccountRepository) FindByUserID(ctx context.Context, userID string) (*domain.Account, error) {
	const q = `
		SELECT id, display_name, billing_email, user_id,
		       COALESCE(lago_customer_id, ''), created_at, updated_at
		FROM accounts WHERE user_id = $1`
	acc := &domain.Account{}
	err := r.pool.QueryRow(ctx, q, userID).Scan(
		&acc.ID, &acc.DisplayName, &acc.BillingEmail, &acc.UserID,
		&acc.LagoCustomerID, &acc.CreatedAt, &acc.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "personal account not found for user "+userID)
	}
	if err != nil {
		return nil, fmt.Errorf("find account by user_id: %w", err)
	}
	return acc, nil
}

// SeatAllowance returns the seat allowance for accountID's active
// plan. When the account has no active account_plans row (never
// subscribed, or the subscription ended and no new one has started),
// returns the personal-account default of 1 — matches the semantics
// of the in-memory adapter and lets fresh personal accounts still
// receive a POST /accounts/{id}/invites response of "seat limit
// reached, upgrade your plan" rather than an infrastructure error.
//
// "Active" plan means an account_plans row where valid_until IS NULL.
// If more than one active row exists (should not, but a bug upstream
// could produce it) we pick the highest seat_allowance — fail
// permissively so a user is never locked out by an accounting glitch.
func (r *AccountRepository) SeatAllowance(ctx context.Context, accountID string) (int, error) {
	const q = `
		SELECT COALESCE(MAX(p.seat_allowance), 1)
		FROM account_plans ap
		JOIN plans p ON p.id = ap.plan_id
		WHERE ap.account_id = $1 AND ap.valid_until IS NULL`
	var n int
	if err := r.pool.QueryRow(ctx, q, accountID).Scan(&n); err != nil {
		return 0, fmt.Errorf("seat allowance: %w", err)
	}
	return n, nil
}

// ListByAccount returns the seats attached to accountID. Empty slice
// (not an error) when accountID is unknown.
func (r *AccountRepository) ListByAccount(ctx context.Context, accountID string) ([]domain.Seat, error) {
	const q = `
		SELECT id, account_id, user_id, role, created_at, updated_at
		FROM account_seats WHERE account_id = $1
		ORDER BY created_at`
	rows, err := r.pool.Query(ctx, q, accountID)
	if err != nil {
		return nil, fmt.Errorf("list seats: %w", err)
	}
	defer rows.Close()

	var seats []domain.Seat
	for rows.Next() {
		var s domain.Seat
		var role string
		if err := rows.Scan(&s.ID, &s.AccountID, &s.UserID, &role, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan seat: %w", err)
		}
		s.Role = domain.Role(role)
		seats = append(seats, s)
	}
	return seats, rows.Err()
}
