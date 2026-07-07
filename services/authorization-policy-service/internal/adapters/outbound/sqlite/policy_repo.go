package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// Compile-time interface check: PolicyRepository must satisfy domain.PolicyRepository.
var _ domain.PolicyRepository = (*PolicyRepository)(nil)

// PolicyRepository is a SQLite-backed implementation of domain.PolicyRepository.
// It stores one row per (subject, role) pair in the subject_roles table,
// mirroring the postgres adapter exactly.
type PolicyRepository struct {
	db *sql.DB
}

// NewPolicyRepository creates a PolicyRepository backed by the given database handle.
func NewPolicyRepository(db *sql.DB) *PolicyRepository {
	return &PolicyRepository{db: db}
}

// FindBySubject returns the policy for subjectID, or an ErrCodeNotFound AppError
// when no policy exists for that subject.
// Roles are returned in alphabetical order (ORDER BY role_name).
func (r *PolicyRepository) FindBySubject(ctx context.Context, subjectID string) (*domain.Policy, error) {
	const query = `SELECT role_name FROM subject_roles WHERE subject_id = ? ORDER BY role_name`

	rows, err := r.db.QueryContext(ctx, query, subjectID)
	if err != nil {
		return nil, fmt.Errorf("querying roles for subject %q: %w", subjectID, err)
	}
	defer func() { _ = rows.Close() }()

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
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction for subject %q: %w", policy.SubjectID, err)
	}
	defer func() { _ = tx.Rollback() }()

	const deleteRoles = `DELETE FROM subject_roles WHERE subject_id = ?`
	if _, err = tx.ExecContext(ctx, deleteRoles, policy.SubjectID); err != nil {
		return fmt.Errorf("deleting roles for subject %q: %w", policy.SubjectID, err)
	}

	const insertRole = `INSERT INTO subject_roles (subject_id, role_name) VALUES (?, ?)`
	for _, role := range policy.Roles {
		if _, err = tx.ExecContext(ctx, insertRole, policy.SubjectID, role); err != nil {
			return fmt.Errorf("inserting role %q for subject %q: %w", role, policy.SubjectID, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction for subject %q: %w", policy.SubjectID, err)
	}
	return nil
}
