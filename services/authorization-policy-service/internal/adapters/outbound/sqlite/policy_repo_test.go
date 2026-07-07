//go:build unit

package sqlite_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/outbound/sqlite"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// setupPolicyRepo returns both repositories sharing one database — assigning
// a role to a subject requires the role to already exist, since
// subject_roles.role_name carries a foreign key to roles(name) (enforced
// here via the foreign_keys pragma; postgres declares the same constraint
// but its integration tests, which never run in CI without
// TEST_DATABASE_URL, don't exercise it).
func setupPolicyRepo(t *testing.T) (*sqlite.PolicyRepository, *sqlite.RoleRepository, *sql.DB) {
	t.Helper()
	db := setupDB(t)
	return sqlite.NewPolicyRepository(db), sqlite.NewRoleRepository(db), db
}

func mustSaveRole(t *testing.T, roleRepo *sqlite.RoleRepository, name string) {
	t.Helper()
	if err := roleRepo.Save(context.Background(), &domain.Role{Name: name}); err != nil {
		t.Fatalf("saving prerequisite role %q: %v", name, err)
	}
}

func TestPolicyRepository_SaveAndFindBySubject(t *testing.T) {
	// Arrange
	policyRepo, roleRepo, _ := setupPolicyRepo(t)
	ctx := context.Background()
	mustSaveRole(t, roleRepo, "admin")
	mustSaveRole(t, roleRepo, "viewer")
	// Roles are stored alphabetically by role_name in subject_roles;
	// FindBySubject returns them in alphabetical order (ORDER BY role_name).
	policy := &domain.Policy{
		SubjectID: "test-subject-save",
		Roles:     []string{"admin", "viewer"},
	}

	// Act
	if err := policyRepo.Save(ctx, policy); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := policyRepo.FindBySubject(ctx, policy.SubjectID)

	// Assert
	if err != nil {
		t.Fatalf("FindBySubject: %v", err)
	}
	if got.SubjectID != policy.SubjectID {
		t.Errorf("SubjectID: got %q, want %q", got.SubjectID, policy.SubjectID)
	}
	if len(got.Roles) != len(policy.Roles) {
		t.Fatalf("Roles length: got %d, want %d", len(got.Roles), len(policy.Roles))
	}
	for i, role := range policy.Roles {
		if got.Roles[i] != role {
			t.Errorf("Roles[%d]: got %q, want %q", i, got.Roles[i], role)
		}
	}
}

func TestPolicyRepository_Save_Upsert(t *testing.T) {
	// Arrange
	policyRepo, roleRepo, _ := setupPolicyRepo(t)
	ctx := context.Background()
	mustSaveRole(t, roleRepo, "admin")
	mustSaveRole(t, roleRepo, "viewer")
	subjectID := "test-subject-upsert"
	if err := policyRepo.Save(ctx, &domain.Policy{SubjectID: subjectID, Roles: []string{"admin"}}); err != nil {
		t.Fatalf("first Save: %v", err)
	}

	// Act
	updated := &domain.Policy{SubjectID: subjectID, Roles: []string{"viewer"}}
	if err := policyRepo.Save(ctx, updated); err != nil {
		t.Fatalf("second Save (upsert): %v", err)
	}
	got, err := policyRepo.FindBySubject(ctx, subjectID)

	// Assert
	if err != nil {
		t.Fatalf("FindBySubject after upsert: %v", err)
	}
	if len(got.Roles) != 1 || got.Roles[0] != "viewer" {
		t.Errorf("after upsert, expected roles=[viewer], got %v", got.Roles)
	}
}

func TestPolicyRepository_FindBySubject_NotFound(t *testing.T) {
	// Arrange
	policyRepo, _, _ := setupPolicyRepo(t)
	ctx := context.Background()

	// Act
	_, err := policyRepo.FindBySubject(ctx, "does-not-exist")

	// Assert
	if !apperrors.IsNotFound(err) {
		t.Errorf("FindBySubject: expected ErrCodeNotFound, got %v", err)
	}
}

func TestSubjectRoles_CascadesOnRoleDeletion(t *testing.T) {
	// Arrange — exercises the ON DELETE CASCADE + foreign_keys pragma path,
	// which is SQLite-specific behavior to verify since the pragma is opt-in
	// (postgres enables foreign key enforcement by default so its schema
	// gets this for free). RoleRepository has no Delete method, so the
	// delete is issued directly against the shared *sql.DB to exercise the
	// constraint the migration declares.
	policyRepo, roleRepo, db := setupPolicyRepo(t)
	ctx := context.Background()
	mustSaveRole(t, roleRepo, "temp-role")
	if err := policyRepo.Save(ctx, &domain.Policy{SubjectID: "cascade-subject", Roles: []string{"temp-role"}}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	if _, err := db.ExecContext(ctx, `DELETE FROM roles WHERE name = ?`, "temp-role"); err != nil {
		t.Fatalf("deleting role directly: %v", err)
	}

	// Assert — the subject_roles row referencing the deleted role must be
	// gone too, leaving the subject with zero roles (not-found, per
	// FindBySubject's "zero rows = not found" semantics).
	_, err := policyRepo.FindBySubject(ctx, "cascade-subject")
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound after cascade delete, got %v", err)
	}
}
