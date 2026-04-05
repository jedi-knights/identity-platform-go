// Package postgres provides a PostgreSQL-backed implementation of domain.UserRepository.
// It uses pgx/v5 for database access and golang-migrate for schema migrations.
// Migrations are embedded at compile time via go:embed so the binary is self-contained.
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

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

//go:embed migrations
var migrationsFS embed.FS

// Compile-time interface check — ensures UserRepository always satisfies domain.UserRepository.
var _ domain.UserRepository = (*UserRepository)(nil)

// UserRepository is a PostgreSQL-backed implementation of domain.UserRepository.
// It is safe for concurrent use because pgxpool manages its own connection pool.
type UserRepository struct {
	pool *pgxpool.Pool
}

// NewUserRepository creates a UserRepository backed by the given connection pool.
// The pool must already be open and healthy; call Connect to obtain one.
func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

// Connect opens a pooled PostgreSQL connection, verifies reachability with a ping,
// and returns the pool. The caller is responsible for calling pool.Close when done.
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

// RunMigrations applies all pending schema migrations embedded in the binary.
// It is idempotent — calling it when the schema is already up to date is safe.
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
	defer db.Close() //nolint:errcheck // migration-only DB handle; close error is benign

	driver, err := pgxmigrate.WithInstance(db, &pgxmigrate.Config{})
	if err != nil {
		return fmt.Errorf("creating migrate driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", d, "pgx5", driver)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("running migrations: %w", err)
	}
	return nil
}

// FindByID retrieves a user by their unique ID.
// Returns an ErrCodeNotFound AppError when no such user exists.
func (r *UserRepository) FindByID(ctx context.Context, id string) (*domain.User, error) {
	var u domain.User
	err := r.pool.QueryRow(ctx,
		`SELECT id, email, name, password_hash, active, created_at, updated_at
		 FROM users WHERE id = $1`,
		id,
	).Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.Active, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("finding user by id: %w", err)
	}
	return &u, nil
}

// FindByEmail retrieves a user by their email address.
// Returns an ErrCodeNotFound AppError when no such user exists.
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	var u domain.User
	err := r.pool.QueryRow(ctx,
		`SELECT id, email, name, password_hash, active, created_at, updated_at
		 FROM users WHERE email = $1`,
		email,
	).Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.Active, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("finding user by email: %w", err)
	}
	return &u, nil
}

// Save persists a new user record. It returns an ErrCodeConflict AppError if the
// email is already registered (PostgreSQL unique-constraint violation 23505).
func (r *UserRepository) Save(ctx context.Context, user *domain.User) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO users (id, email, name, password_hash, active)
		 VALUES ($1, $2, $3, $4, $5)`,
		user.ID, user.Email, user.Name, user.PasswordHash, user.Active,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return apperrors.New(apperrors.ErrCodeConflict, "email already registered")
		}
		return fmt.Errorf("saving user: %w", err)
	}
	return nil
}

// Update replaces a user's mutable fields. Returns an ErrCodeNotFound AppError
// when no row with the given ID exists.
func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE users
		 SET email = $2, name = $3, password_hash = $4, active = $5, updated_at = now()
		 WHERE id = $1`,
		user.ID, user.Email, user.Name, user.PasswordHash, user.Active,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return apperrors.New(apperrors.ErrCodeConflict, "email already registered")
		}
		return fmt.Errorf("updating user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return apperrors.New(apperrors.ErrCodeNotFound, "user not found")
	}
	return nil
}

// isUniqueViolation reports whether err is a PostgreSQL unique-constraint violation
// (SQLSTATE 23505). It is used to distinguish duplicate-email inserts from other
// database errors so the service can return a domain-level ErrCodeConflict.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
