//go:build unit

package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/outbound/sqlite"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// setupDB opens a fresh, uniquely-named SQLite file under t.TempDir() so
// every test gets its own isolated database — no shared state, no
// TEST_DATABASE_URL, no external service required.
func setupDB(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "policy.db")

	migrationDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening migration connection: %v", err)
	}
	if err := sqlite.RunMigrations(ctx, migrationDB); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if err := migrationDB.Close(); err != nil {
		t.Fatalf("closing migration connection: %v", err)
	}

	db, err := sqlite.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func setupRoleRepo(t *testing.T) *sqlite.RoleRepository {
	t.Helper()
	return sqlite.NewRoleRepository(setupDB(t))
}

func TestRoleRepository_SaveAndFindByName(t *testing.T) {
	// Arrange
	repo := setupRoleRepo(t)
	ctx := context.Background()
	role := &domain.Role{
		Name: "test-editor",
		Permissions: []domain.Permission{
			{Resource: "article", Action: "read"},
			{Resource: "article", Action: "write"},
		},
	}

	// Act
	if err := repo.Save(ctx, role); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := repo.FindByName(ctx, role.Name)

	// Assert
	if err != nil {
		t.Fatalf("FindByName: %v", err)
	}
	if got.Name != role.Name {
		t.Errorf("Name: got %q, want %q", got.Name, role.Name)
	}
	if len(got.Permissions) != len(role.Permissions) {
		t.Fatalf("Permissions length: got %d, want %d", len(got.Permissions), len(role.Permissions))
	}
	// Results are ordered by (resource, action), same order as the fixture.
	for i, perm := range role.Permissions {
		if got.Permissions[i].Resource != perm.Resource || got.Permissions[i].Action != perm.Action {
			t.Errorf("Permissions[%d]: got (%s, %s), want (%s, %s)",
				i, got.Permissions[i].Resource, got.Permissions[i].Action,
				perm.Resource, perm.Action)
		}
	}
}

func TestRoleRepository_Save_ReplacesPermissions(t *testing.T) {
	// Arrange
	repo := setupRoleRepo(t)
	ctx := context.Background()
	name := "test-replaceable"
	if err := repo.Save(ctx, &domain.Role{
		Name:        name,
		Permissions: []domain.Permission{{Resource: "x", Action: "read"}},
	}); err != nil {
		t.Fatalf("first Save: %v", err)
	}

	// Act
	updated := &domain.Role{
		Name:        name,
		Permissions: []domain.Permission{{Resource: "y", Action: "write"}},
	}
	if err := repo.Save(ctx, updated); err != nil {
		t.Fatalf("second Save (replace): %v", err)
	}
	got, err := repo.FindByName(ctx, name)

	// Assert
	if err != nil {
		t.Fatalf("FindByName after replace: %v", err)
	}
	if len(got.Permissions) != 1 ||
		got.Permissions[0].Resource != "y" ||
		got.Permissions[0].Action != "write" {
		t.Errorf("after replace, expected [(y,write)], got %v", got.Permissions)
	}
}

func TestRoleRepository_Save_NoPermissions(t *testing.T) {
	// Arrange
	repo := setupRoleRepo(t)
	ctx := context.Background()
	role := &domain.Role{Name: "test-empty", Permissions: []domain.Permission{}}

	// Act
	if err := repo.Save(ctx, role); err != nil {
		t.Fatalf("Save empty permissions: %v", err)
	}
	got, err := repo.FindByName(ctx, role.Name)

	// Assert
	if err != nil {
		t.Fatalf("FindByName: %v", err)
	}
	if len(got.Permissions) != 0 {
		t.Errorf("expected no permissions, got %v", got.Permissions)
	}
}

func TestRoleRepository_Save_UpsertDoesNotDuplicateRoleRow(t *testing.T) {
	// Arrange — exercises the "INSERT ... ON CONFLICT (name) DO NOTHING" path
	// SQLite-specifically, since the syntax differs enough from postgres's
	// that it's worth a dedicated assertion rather than trusting the postgres
	// test's coverage to carry over.
	repo := setupRoleRepo(t)
	ctx := context.Background()
	name := "test-upsert-twice"
	if err := repo.Save(ctx, &domain.Role{Name: name, Permissions: []domain.Permission{{Resource: "a", Action: "read"}}}); err != nil {
		t.Fatalf("first Save: %v", err)
	}

	// Act
	err := repo.Save(ctx, &domain.Role{Name: name, Permissions: []domain.Permission{{Resource: "b", Action: "write"}}})

	// Assert
	if err != nil {
		t.Fatalf("second Save should upsert without error, got: %v", err)
	}
	got, err := repo.FindByName(ctx, name)
	if err != nil {
		t.Fatalf("FindByName: %v", err)
	}
	if len(got.Permissions) != 1 || got.Permissions[0].Resource != "b" {
		t.Errorf("expected permissions replaced with [(b,write)], got %v", got.Permissions)
	}
}

func TestRoleRepository_FindByName_NotFound(t *testing.T) {
	// Arrange
	repo := setupRoleRepo(t)
	ctx := context.Background()

	// Act
	_, err := repo.FindByName(ctx, "ghost-role")

	// Assert
	if !apperrors.IsNotFound(err) {
		t.Errorf("FindByName: expected ErrCodeNotFound, got %v", err)
	}
}

func TestRunMigrations_Idempotent(t *testing.T) {
	// Arrange
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "idempotent.db")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Act
	if err := sqlite.RunMigrations(ctx, db); err != nil {
		t.Fatalf("first RunMigrations: %v", err)
	}
	err = sqlite.RunMigrations(ctx, db)

	// Assert
	if err != nil {
		t.Fatalf("second RunMigrations should be a no-op, got error: %v", err)
	}
}
