//go:build integration

package postgres_test

import (
	"context"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

func TestRoleRepository_FindByNames_ReturnsExistingAndOmitsUnknown(t *testing.T) {
	repo := setupRoleRepo(t)
	ctx := context.Background()
	a, b, empty, ghost := t.Name()+"-a", t.Name()+"-b", t.Name()+"-empty", t.Name()+"-ghost"
	for _, r := range []*domain.Role{
		{Name: a, Permissions: []domain.Permission{{Resource: "doc", Action: "read"}, {Resource: "doc", Action: "write"}}},
		{Name: b, Permissions: []domain.Permission{{Resource: "img", Action: "read"}}},
		{Name: empty, Permissions: []domain.Permission{}},
	} {
		if err := repo.Save(ctx, r); err != nil {
			t.Fatalf("Save %s: %v", r.Name, err)
		}
	}

	got, err := repo.FindByNames(ctx, []string{b, ghost, a, empty})
	if err != nil {
		t.Fatalf("FindByNames: %v", err)
	}

	assertFoundRoles(t, got, a, empty, ghost)
}

// assertFoundRoles checks that exactly the three existing roles came back, the
// unknown name is absent, role a kept both permissions, and the permission-less
// role is returned empty rather than dropped.
func assertFoundRoles(t *testing.T, got []*domain.Role, a, empty, ghost string) {
	t.Helper()
	byName := map[string]*domain.Role{}
	for _, r := range got {
		byName[r.Name] = r
	}
	if len(got) != 3 || byName[ghost] != nil {
		t.Fatalf("got %d roles %v; want exactly the 3 that exist, none for the unknown name", len(got), got)
	}
	if n := len(byName[a].Permissions); n != 2 {
		t.Errorf("role %s has %d permissions, want 2", a, n)
	}
	if byName[empty] == nil || len(byName[empty].Permissions) != 0 {
		t.Errorf("role %s should be returned with no permissions, got %+v", empty, byName[empty])
	}
}

func TestRoleRepository_FindByNames_EmptyInput(t *testing.T) {
	repo := setupRoleRepo(t)

	got, err := repo.FindByNames(context.Background(), nil)

	if err != nil || len(got) != 0 {
		t.Fatalf("want no roles and no error for no names, got %v, %v", got, err)
	}
}

// assertPermissions fails unless got has exactly the wanted permissions in the
// wanted order. Extracted so the repository tests stay within the project's
// cyclomatic-complexity limit.
func assertPermissions(t *testing.T, got, want []domain.Permission) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("Permissions length: got %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("Permissions[%d]: got %+v, want %+v", i, got[i], w)
		}
	}
}
