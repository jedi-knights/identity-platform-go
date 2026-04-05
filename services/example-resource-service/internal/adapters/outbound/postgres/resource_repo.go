// Package postgres provides a PostgreSQL-backed implementation of domain.ResourceRepository.
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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/domain"
)

//go:embed migrations
var migrationsFS embed.FS

// Compile-time interface check — ensures ResourceRepository always satisfies domain.ResourceRepository.
var _ domain.ResourceRepository = (*ResourceRepository)(nil)

// ResourceRepository is a PostgreSQL-backed implementation of domain.ResourceRepository.
// It is safe for concurrent use because pgxpool manages its own connection pool.
type ResourceRepository struct {
	pool *pgxpool.Pool
}

// NewResourceRepository creates a ResourceRepository backed by the given connection pool.
// The pool must already be open and healthy; call Connect to obtain one.
func NewResourceRepository(pool *pgxpool.Pool) *ResourceRepository {
	return &ResourceRepository{pool: pool}
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
	defer db.Close() //nolint:errcheck

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

// FindByID retrieves a resource by its unique ID.
// Returns an ErrCodeNotFound AppError when no such resource exists.
func (r *ResourceRepository) FindByID(ctx context.Context, id string) (*domain.Resource, error) {
	var res domain.Resource
	err := r.pool.QueryRow(ctx,
		`SELECT id, name, description, owner_id, created_at
		 FROM resources WHERE id = $1`,
		id,
	).Scan(&res.ID, &res.Name, &res.Description, &res.OwnerID, &res.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "resource not found")
	}
	if err != nil {
		return nil, fmt.Errorf("finding resource by id: %w", err)
	}
	return &res, nil
}

// FindAll retrieves all resources from the database.
// Returns an empty slice (not nil) when no resources exist.
func (r *ResourceRepository) FindAll(ctx context.Context) ([]*domain.Resource, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, name, description, owner_id, created_at FROM resources ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("querying resources: %w", err)
	}
	defer rows.Close()

	var results []*domain.Resource
	for rows.Next() {
		var res domain.Resource
		if err := rows.Scan(&res.ID, &res.Name, &res.Description, &res.OwnerID, &res.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning resource row: %w", err)
		}
		results = append(results, &res)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating resource rows: %w", err)
	}
	if results == nil {
		results = []*domain.Resource{}
	}
	return results, nil
}

// Save persists a resource, inserting it or replacing the existing record for the same ID
// (upsert). This mirrors the memory adapter's overwrite-on-conflict behaviour.
func (r *ResourceRepository) Save(ctx context.Context, resource *domain.Resource) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO resources (id, name, description, owner_id, created_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (id) DO UPDATE
		   SET name        = EXCLUDED.name,
		       description = EXCLUDED.description,
		       owner_id    = EXCLUDED.owner_id`,
		resource.ID, resource.Name, resource.Description, resource.OwnerID, resource.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("saving resource: %w", err)
	}
	return nil
}
