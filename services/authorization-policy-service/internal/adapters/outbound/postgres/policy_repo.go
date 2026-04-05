// Package postgres provides PostgreSQL-backed repository implementations for the
// authorization-policy-service. All adapters are safe for concurrent use.
//
// Connection management is handled through a [pgxpool.Pool] created by [Connect].
// Schema migrations are applied by [RunMigrations] and must be called before
// any repository is used against a fresh database.
package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres" // postgres driver
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Compile-time interface check: PolicyRepository must satisfy domain.PolicyRepository.
var _ domain.PolicyRepository = (*PolicyRepository)(nil)

// PolicyRepository is a PostgreSQL-backed implementation of domain.PolicyRepository.
// It stores one row per (subject, role) pair in the subject_roles join table,
// satisfying 1NF by eliminating the TEXT[] repeating-group from the old policies table.
type PolicyRepository struct {
	pool *pgxpool.Pool
}

// NewPolicyRepository creates a PolicyRepository backed by the provided connection pool.
func NewPolicyRepository(pool *pgxpool.Pool) *PolicyRepository {
	return &PolicyRepository{pool: pool}
}

// Connect establishes a pgxpool connection to databaseURL and verifies connectivity.
// Callers are responsible for calling pool.Close() when the pool is no longer needed.
func Connect(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("creating pgxpool: %w", err)
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}
	return pool, nil
}

// RunMigrations applies all pending up-migrations embedded in the migrations directory
// against the database at databaseURL. It is idempotent — running it against an
// already-migrated database is safe and returns nil.
func RunMigrations(databaseURL string) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("loading migration sources: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, databaseURL)
	if err != nil {
		return fmt.Errorf("creating migrate instance: %w", err)
	}
	if err = m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("running migrations: %w", err)
	}
	return nil
}

// FindBySubject returns the policy for subjectID, or an ErrCodeNotFound AppError
// when no policy exists for that subject.
// Roles are returned in alphabetical order (ORDER BY role_name).
func (r *PolicyRepository) FindBySubject(ctx context.Context, subjectID string) (*domain.Policy, error) {
	const query = `SELECT role_name FROM subject_roles WHERE subject_id = $1 ORDER BY role_name`

	rows, err := r.pool.Query(ctx, query, subjectID)
	if err != nil {
		return nil, fmt.Errorf("querying roles for subject %q: %w", subjectID, err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var roleName string
		if err = rows.Scan(&roleName); err != nil {
			return nil, fmt.Errorf("scanning role for subject %q: %w", subjectID, err)
		}
		roles = append(roles, roleName)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating roles for subject %q: %w", subjectID, err)
	}

	if len(roles) == 0 {
		// Distinguish "subject exists with no roles" from "subject never saved":
		// zero rows returned means no rows exist for this subject_id — not found.
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "policy not found")
	}

	return &domain.Policy{SubjectID: subjectID, Roles: roles}, nil
}

// Save persists the policy. The operation is atomic: all existing rows for the
// subject are deleted and the new role set is inserted in a single transaction.
// If policy.Roles is empty the subject's rows are deleted and the subject simply
// has no roles — this is valid and returns nil.
func (r *PolicyRepository) Save(ctx context.Context, policy *domain.Policy) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction for subject %q: %w", policy.SubjectID, err)
	}
	defer func() {
		// Rollback is a no-op when the transaction has already been committed.
		_ = tx.Rollback(ctx)
	}()

	const deleteRoles = `DELETE FROM subject_roles WHERE subject_id = $1`
	if _, err = tx.Exec(ctx, deleteRoles, policy.SubjectID); err != nil {
		return fmt.Errorf("deleting roles for subject %q: %w", policy.SubjectID, err)
	}

	const insertRole = `INSERT INTO subject_roles (subject_id, role_name) VALUES ($1, $2)`
	for _, role := range policy.Roles {
		if _, err = tx.Exec(ctx, insertRole, policy.SubjectID, role); err != nil {
			return fmt.Errorf("inserting role %q for subject %q: %w", role, policy.SubjectID, err)
		}
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction for subject %q: %w", policy.SubjectID, err)
	}
	return nil
}
