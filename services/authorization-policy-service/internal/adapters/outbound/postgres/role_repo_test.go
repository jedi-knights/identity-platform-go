//go:build integration

package postgres_test

import (
	"context"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/outbound/postgres"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

func setupRoleRepo(t *testing.T) *postgres.RoleRepository {
	t.Helper()
	url := testDatabaseURL(t)
	if err := postgres.RunMigrations(url); err != nil {
		t.Fatalf("running migrations: %v", err)
	}
	pool, err := postgres.Connect(context.Background(), url)
	if err != nil {
		t.Fatalf("connecting to database: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return postgres.NewRoleRepository(pool)
}

func TestRoleRepository_SaveAndFindByName(t *testing.T) {
	repo := setupRoleRepo(t)
	ctx := context.Background()

	role := &domain.Role{
		Name: "test-editor",
		Permissions: []domain.Permission{
			{Resource: "article", Action: "read"},
			{Resource: "article", Action: "write"},
		},
	}

	if err := repo.Save(ctx, role); err != nil {
		t.Fatalf("Save: unexpected error: %v", err)
	}

	got, err := repo.FindByName(ctx, role.Name)
	if err != nil {
		t.Fatalf("FindByName: unexpected error: %v", err)
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
	repo := setupRoleRepo(t)
	ctx := context.Background()

	name := "test-replaceable"

	if err := repo.Save(ctx, &domain.Role{
		Name:        name,
		Permissions: []domain.Permission{{Resource: "x", Action: "read"}},
	}); err != nil {
		t.Fatalf("first Save: unexpected error: %v", err)
	}

	updated := &domain.Role{
		Name:        name,
		Permissions: []domain.Permission{{Resource: "y", Action: "write"}},
	}
	if err := repo.Save(ctx, updated); err != nil {
		t.Fatalf("second Save (replace): unexpected error: %v", err)
	}

	got, err := repo.FindByName(ctx, name)
	if err != nil {
		t.Fatalf("FindByName after replace: unexpected error: %v", err)
	}
	if len(got.Permissions) != 1 ||
		got.Permissions[0].Resource != "y" ||
		got.Permissions[0].Action != "write" {
		t.Errorf("after replace, expected [(y,write)], got %v", got.Permissions)
	}
}

func TestRoleRepository_Save_NoPermissions(t *testing.T) {
	repo := setupRoleRepo(t)
	ctx := context.Background()

	role := &domain.Role{Name: "test-empty", Permissions: []domain.Permission{}}
	if err := repo.Save(ctx, role); err != nil {
		t.Fatalf("Save empty permissions: unexpected error: %v", err)
	}

	got, err := repo.FindByName(ctx, role.Name)
	if err != nil {
		t.Fatalf("FindByName: unexpected error: %v", err)
	}
	if len(got.Permissions) != 0 {
		t.Errorf("expected no permissions, got %v", got.Permissions)
	}
}

func TestRoleRepository_FindByName_NotFound(t *testing.T) {
	repo := setupRoleRepo(t)
	ctx := context.Background()

	_, err := repo.FindByName(ctx, "ghost-role")
	if err == nil {
		t.Fatal("FindByName: expected error, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("FindByName: expected ErrCodeNotFound, got %v", err)
	}
}
