//go:build integration

package postgres_test

import (
	"context"
	"os"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/outbound/postgres"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	return url
}

func setupPolicyRepo(t *testing.T) *postgres.PolicyRepository {
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
	return postgres.NewPolicyRepository(pool)
}

func TestPolicyRepository_SaveAndFindBySubject(t *testing.T) {
	repo := setupPolicyRepo(t)
	ctx := context.Background()

	// Roles are stored alphabetically by role_name in subject_roles;
	// FindBySubject returns them in alphabetical order (ORDER BY role_name).
	policy := &domain.Policy{
		SubjectID: "test-subject-save",
		Roles:     []string{"admin", "viewer"},
	}

	if err := repo.Save(ctx, policy); err != nil {
		t.Fatalf("Save: unexpected error: %v", err)
	}

	got, err := repo.FindBySubject(ctx, policy.SubjectID)
	if err != nil {
		t.Fatalf("FindBySubject: unexpected error: %v", err)
	}

	if got.SubjectID != policy.SubjectID {
		t.Errorf("SubjectID: got %q, want %q", got.SubjectID, policy.SubjectID)
	}
	if len(got.Roles) != len(policy.Roles) {
		t.Fatalf("Roles length: got %d, want %d", len(got.Roles), len(policy.Roles))
	}
	// Both slices are sorted alphabetically, so index-based comparison is stable.
	for i, role := range policy.Roles {
		if got.Roles[i] != role {
			t.Errorf("Roles[%d]: got %q, want %q", i, got.Roles[i], role)
		}
	}
}

func TestPolicyRepository_Save_Upsert(t *testing.T) {
	repo := setupPolicyRepo(t)
	ctx := context.Background()

	subjectID := "test-subject-upsert"

	if err := repo.Save(ctx, &domain.Policy{SubjectID: subjectID, Roles: []string{"admin"}}); err != nil {
		t.Fatalf("first Save: unexpected error: %v", err)
	}

	updated := &domain.Policy{SubjectID: subjectID, Roles: []string{"viewer"}}
	if err := repo.Save(ctx, updated); err != nil {
		t.Fatalf("second Save (upsert): unexpected error: %v", err)
	}

	got, err := repo.FindBySubject(ctx, subjectID)
	if err != nil {
		t.Fatalf("FindBySubject after upsert: unexpected error: %v", err)
	}
	if len(got.Roles) != 1 || got.Roles[0] != "viewer" {
		t.Errorf("after upsert, expected roles=[viewer], got %v", got.Roles)
	}
}

func TestPolicyRepository_FindBySubject_NotFound(t *testing.T) {
	repo := setupPolicyRepo(t)
	ctx := context.Background()

	_, err := repo.FindBySubject(ctx, "does-not-exist")
	if err == nil {
		t.Fatal("FindBySubject: expected error, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("FindBySubject: expected ErrCodeNotFound, got %v", err)
	}
}
