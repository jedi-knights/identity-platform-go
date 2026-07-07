package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/domain"
)

// Compile-time interface check — ensures ResourceRepository always satisfies domain.ResourceRepository.
var _ domain.ResourceRepository = (*ResourceRepository)(nil)

// ResourceRepository is a SQLite-backed implementation of domain.ResourceRepository.
// Safe for concurrent use; *sql.DB manages its own connection pool.
type ResourceRepository struct {
	db *sql.DB
}

// NewResourceRepository creates a ResourceRepository backed by the given
// database handle. The handle must already be open; call Connect to obtain one.
func NewResourceRepository(db *sql.DB) *ResourceRepository {
	return &ResourceRepository{db: db}
}

// FindByID retrieves a resource by its unique ID.
// Returns an ErrCodeNotFound AppError when no such resource exists.
func (r *ResourceRepository) FindByID(ctx context.Context, id string) (*domain.Resource, error) {
	var res domain.Resource
	var createdAt string
	err := r.db.QueryRowContext(ctx,
		`SELECT id, name, description, owner_id, created_at
		 FROM resources WHERE id = ?`,
		id,
	).Scan(&res.ID, &res.Name, &res.Description, &res.OwnerID, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "resource not found")
	}
	if err != nil {
		return nil, fmt.Errorf("finding resource by id: %w", err)
	}
	if res.CreatedAt, err = textToTime(createdAt); err != nil {
		return nil, fmt.Errorf("parsing created_at for resource %q: %w", res.ID, err)
	}
	return &res, nil
}

// FindAll retrieves all resources from the database, ordered by creation time.
// Returns an empty slice (not nil) when no resources exist.
func (r *ResourceRepository) FindAll(ctx context.Context) ([]*domain.Resource, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, description, owner_id, created_at FROM resources ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("querying resources: %w", err)
	}
	defer func() { _ = rows.Close() }()

	results := []*domain.Resource{}
	for rows.Next() {
		var res domain.Resource
		var createdAt string
		if err := rows.Scan(&res.ID, &res.Name, &res.Description, &res.OwnerID, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning resource row: %w", err)
		}
		if res.CreatedAt, err = textToTime(createdAt); err != nil {
			return nil, fmt.Errorf("parsing created_at for resource %q: %w", res.ID, err)
		}
		results = append(results, &res)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating resource rows: %w", err)
	}
	return results, nil
}

// Save persists a resource, inserting it or replacing the existing record for the same ID
// (upsert). This mirrors the memory and postgres adapters' overwrite-on-conflict behavior.
// created_at is intentionally excluded from the UPDATE clause, matching postgres's
// "ON CONFLICT ... DO UPDATE SET name=..., description=..., owner_id=..." (no created_at) —
// the original creation time is preserved across an upsert.
func (r *ResourceRepository) Save(ctx context.Context, resource *domain.Resource) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO resources (id, name, description, owner_id, created_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (id) DO UPDATE
		   SET name        = excluded.name,
		       description = excluded.description,
		       owner_id    = excluded.owner_id`,
		resource.ID, resource.Name, resource.Description, resource.OwnerID, timeToText(resource.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("saving resource: %w", err)
	}
	return nil
}
