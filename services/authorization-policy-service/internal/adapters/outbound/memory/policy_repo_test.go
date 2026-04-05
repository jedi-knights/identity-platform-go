//go:build unit

package memory_test

import (
	"context"
	"errors"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// --- PolicyRepository ---

func TestPolicyRepository_FindBySubject_Seeded(t *testing.T) {
	repo := memory.NewPolicyRepository()
	ctx := context.Background()

	// user-1 and user-2 are seeded in NewPolicyRepository.
	got, err := repo.FindBySubject(ctx, "user-1")
	if err != nil {
		t.Fatalf("FindBySubject: %v", err)
	}
	if got.SubjectID != "user-1" {
		t.Errorf("SubjectID = %q, want %q", got.SubjectID, "user-1")
	}
	if len(got.Roles) == 0 {
		t.Error("expected at least one role, got none")
	}
}

func TestPolicyRepository_FindBySubject_NotFound(t *testing.T) {
	repo := memory.NewPolicyRepository()
	ctx := context.Background()

	_, err := repo.FindBySubject(ctx, "unknown-subject")
	if err == nil {
		t.Fatal("expected error for unknown subject, got nil")
	}
	var appErr *apperrors.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected *apperrors.AppError, got: %T %v", err, err)
	}
	if appErr.Code() != apperrors.ErrCodeNotFound {
		t.Errorf("expected ErrCodeNotFound, got: %s", appErr.Code())
	}
}

func TestPolicyRepository_Save_NewEntry(t *testing.T) {
	repo := memory.NewPolicyRepository()
	ctx := context.Background()

	p := &domain.Policy{SubjectID: "new-user", Roles: []string{"viewer"}}
	if err := repo.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindBySubject(ctx, "new-user")
	if err != nil {
		t.Fatalf("FindBySubject after Save: %v", err)
	}
	if got.SubjectID != "new-user" {
		t.Errorf("SubjectID = %q, want %q", got.SubjectID, "new-user")
	}
}

func TestPolicyRepository_Save_OverwritesExisting(t *testing.T) {
	repo := memory.NewPolicyRepository()
	ctx := context.Background()

	updated := &domain.Policy{SubjectID: "user-1", Roles: []string{"viewer", "editor"}}
	if err := repo.Save(ctx, updated); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindBySubject(ctx, "user-1")
	if err != nil {
		t.Fatalf("FindBySubject after Save: %v", err)
	}
	if len(got.Roles) != 2 {
		t.Errorf("Roles len = %d, want 2", len(got.Roles))
	}
	if got.Roles[0] != "viewer" || got.Roles[1] != "editor" {
		t.Errorf("Roles = %v, want [viewer editor]", got.Roles)
	}
}

func TestPolicyRepository_FindBySubject_ReturnsCopy(t *testing.T) {
	// Mutating the returned policy must not affect the stored entry.
	repo := memory.NewPolicyRepository()
	ctx := context.Background()

	got, err := repo.FindBySubject(ctx, "user-1")
	if err != nil {
		t.Fatalf("FindBySubject: %v", err)
	}
	originalRoles := make([]string, len(got.Roles))
	copy(originalRoles, got.Roles)

	got.Roles = append(got.Roles, "injected-role")

	got2, err := repo.FindBySubject(ctx, "user-1")
	if err != nil {
		t.Fatalf("second FindBySubject: %v", err)
	}
	if len(got2.Roles) != len(originalRoles) {
		t.Errorf("stored roles mutated: got %d roles, want %d", len(got2.Roles), len(originalRoles))
	}
}

// --- RoleRepository ---

func TestRoleRepository_FindByName_Seeded(t *testing.T) {
	repo := memory.NewRoleRepository()
	ctx := context.Background()

	got, err := repo.FindByName(ctx, "admin")
	if err != nil {
		t.Fatalf("FindByName: %v", err)
	}
	if got.Name != "admin" {
		t.Errorf("Name = %q, want %q", got.Name, "admin")
	}
	if len(got.Permissions) == 0 {
		t.Error("expected at least one permission, got none")
	}
}

func TestRoleRepository_FindByName_NotFound(t *testing.T) {
	repo := memory.NewRoleRepository()
	ctx := context.Background()

	_, err := repo.FindByName(ctx, "nonexistent-role")
	if err == nil {
		t.Fatal("expected error for unknown role, got nil")
	}
	var appErr *apperrors.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected *apperrors.AppError, got: %T %v", err, err)
	}
	if appErr.Code() != apperrors.ErrCodeNotFound {
		t.Errorf("expected ErrCodeNotFound, got: %s", appErr.Code())
	}
}

func TestRoleRepository_Save_NewEntry(t *testing.T) {
	repo := memory.NewRoleRepository()
	ctx := context.Background()

	role := &domain.Role{
		Name: "editor",
		Permissions: []domain.Permission{
			{Resource: "document", Action: "write"},
		},
	}
	if err := repo.Save(ctx, role); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindByName(ctx, "editor")
	if err != nil {
		t.Fatalf("FindByName after Save: %v", err)
	}
	if got.Name != "editor" {
		t.Errorf("Name = %q, want %q", got.Name, "editor")
	}
}

func TestRoleRepository_Save_OverwritesExisting(t *testing.T) {
	repo := memory.NewRoleRepository()
	ctx := context.Background()

	updated := &domain.Role{
		Name: "viewer",
		Permissions: []domain.Permission{
			{Resource: "document", Action: "read"},
			{Resource: "document", Action: "list"},
		},
	}
	if err := repo.Save(ctx, updated); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindByName(ctx, "viewer")
	if err != nil {
		t.Fatalf("FindByName after Save: %v", err)
	}
	if len(got.Permissions) != 2 {
		t.Errorf("Permissions len = %d, want 2", len(got.Permissions))
	}
	if got.Permissions[0].Resource != "document" || got.Permissions[0].Action != "read" {
		t.Errorf("Permissions[0] = %+v, want {document read}", got.Permissions[0])
	}
	if got.Permissions[1].Resource != "document" || got.Permissions[1].Action != "list" {
		t.Errorf("Permissions[1] = %+v, want {document list}", got.Permissions[1])
	}
}

func TestRoleRepository_FindByName_ReturnsCopy(t *testing.T) {
	// Mutating the returned role must not affect the stored entry.
	repo := memory.NewRoleRepository()
	ctx := context.Background()

	got, err := repo.FindByName(ctx, "admin")
	if err != nil {
		t.Fatalf("FindByName: %v", err)
	}
	originalLen := len(got.Permissions)

	got.Permissions = append(got.Permissions, domain.Permission{Resource: "injected", Action: "delete"})

	got2, err := repo.FindByName(ctx, "admin")
	if err != nil {
		t.Fatalf("second FindByName: %v", err)
	}
	if len(got2.Permissions) != originalLen {
		t.Errorf("stored permissions mutated: got %d, want %d", len(got2.Permissions), originalLen)
	}
}
