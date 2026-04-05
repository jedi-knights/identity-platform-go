package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// Compile-time interface check: RoleRepository must satisfy domain.RoleRepository.
var _ domain.RoleRepository = (*RoleRepository)(nil)

// RoleRepository is a PostgreSQL-backed implementation of domain.RoleRepository.
// Each role row is stored in the roles table; its permissions live in role_permissions.
type RoleRepository struct {
	pool *pgxpool.Pool
}

// NewRoleRepository creates a RoleRepository backed by the provided connection pool.
func NewRoleRepository(pool *pgxpool.Pool) *RoleRepository {
	return &RoleRepository{pool: pool}
}

// FindByName returns the role with the given name, including all of its permissions.
// It returns an ErrCodeNotFound AppError when no role exists with that name.
// The query performs a LEFT JOIN so a role with no permissions is returned as an
// empty slice rather than causing a not-found error.
func (r *RoleRepository) FindByName(ctx context.Context, name string) (*domain.Role, error) {
	const query = `
		SELECT r.name, rp.resource, rp.action
		FROM   roles r
		LEFT JOIN role_permissions rp ON rp.role_name = r.name
		WHERE  r.name = $1
		ORDER  BY rp.resource, rp.action`

	rows, err := r.pool.Query(ctx, query, name)
	if err != nil {
		return nil, fmt.Errorf("querying role %q: %w", name, err)
	}
	defer rows.Close()

	var role *domain.Role
	for rows.Next() {
		var roleName string
		var resource, action *string // nullable due to LEFT JOIN
		if err = rows.Scan(&roleName, &resource, &action); err != nil {
			return nil, fmt.Errorf("scanning role row for %q: %w", name, err)
		}
		if role == nil {
			role = &domain.Role{Name: roleName, Permissions: []domain.Permission{}}
		}
		appendNullablePermission(role, resource, action)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating role rows for %q: %w", name, err)
	}

	if role == nil {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "role not found")
	}
	return role, nil
}

// appendNullablePermission appends a domain.Permission to role only when both
// resource and action are non-nil (LEFT JOIN columns that are NULL for a role
// with no permissions). Extracted from FindByName to keep its cyclomatic
// complexity within bounds.
func appendNullablePermission(role *domain.Role, resource, action *string) {
	if resource != nil && action != nil {
		role.Permissions = append(role.Permissions, domain.Permission{
			Resource: *resource,
			Action:   *action,
		})
	}
}

// Save persists the role and its permissions atomically inside a transaction.
// If the role already exists the existing permissions are replaced: all prior
// role_permissions rows are deleted and the new set is inserted. This avoids
// partial-update anomalies while keeping the implementation simple.
func (r *RoleRepository) Save(ctx context.Context, role *domain.Role) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction for role %q: %w", role.Name, err)
	}
	defer func() {
		// Rollback is a no-op when the transaction has already been committed.
		_ = tx.Rollback(ctx)
	}()

	// Upsert the role row.
	const upsertRole = `
		INSERT INTO roles (name)
		VALUES ($1)
		ON CONFLICT (name) DO NOTHING`
	if _, err = tx.Exec(ctx, upsertRole, role.Name); err != nil {
		return fmt.Errorf("upserting role %q: %w", role.Name, err)
	}

	// Replace all permissions for this role.
	const deletePerms = `DELETE FROM role_permissions WHERE role_name = $1`
	if _, err = tx.Exec(ctx, deletePerms, role.Name); err != nil {
		return fmt.Errorf("deleting permissions for role %q: %w", role.Name, err)
	}

	const insertPerm = `
		INSERT INTO role_permissions (role_name, resource, action)
		VALUES ($1, $2, $3)`
	for _, perm := range role.Permissions {
		if _, err = tx.Exec(ctx, insertPerm, role.Name, perm.Resource, perm.Action); err != nil {
			return fmt.Errorf("inserting permission (%s, %s) for role %q: %w",
				perm.Resource, perm.Action, role.Name, err)
		}
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction for role %q: %w", role.Name, err)
	}
	return nil
}
