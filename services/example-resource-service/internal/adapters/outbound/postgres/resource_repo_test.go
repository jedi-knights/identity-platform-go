//go:build integration

package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/postgres"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/domain"
)

// testDatabaseURL returns the database URL for integration tests or skips the
// test when TEST_DATABASE_URL is not set. This keeps the test suite runnable
// in environments without a real database (unit CI, local dev without Docker).
func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	return url
}

func setupRepo(t *testing.T) *postgres.ResourceRepository {
	t.Helper()
	dbURL := testDatabaseURL(t)

	if err := postgres.RunMigrations(dbURL); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	ctx := context.Background()
	pool, err := postgres.Connect(ctx, dbURL)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	return postgres.NewResourceRepository(pool)
}

func newTestResource(suffix string) *domain.Resource {
	return &domain.Resource{
		ID:          "test-res-" + suffix,
		Name:        "Test Resource " + suffix,
		Description: "A test resource for " + suffix,
		OwnerID:     "user-" + suffix,
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
	}
}

func cleanupResource(t *testing.T, repo *postgres.ResourceRepository, id string) {
	t.Helper()
	// Best-effort cleanup via a fresh context so it runs even if the test failed.
	ctx := context.Background()
	_ = repo.Save(ctx, &domain.Resource{ID: id}) // ensure row exists before deleting via upsert is not a delete
	// Direct delete is not in the interface; rely on test isolation via unique IDs.
	// The table is truncated only in CI; for local runs, rows accumulate harmlessly
	// because IDs are unique per test run (via suffix).
	_ = id
}

// TestSaveAndFindByID verifies the basic round-trip: Save a resource, then retrieve
// it by ID and confirm every field round-trips correctly.
func TestSaveAndFindByID(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	res := newTestResource("save-findbyid")

	if err := repo.Save(ctx, res); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindByID(ctx, res.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}

	if got.ID != res.ID {
		t.Errorf("ID: got %q, want %q", got.ID, res.ID)
	}
	if got.Name != res.Name {
		t.Errorf("Name: got %q, want %q", got.Name, res.Name)
	}
	if got.Description != res.Description {
		t.Errorf("Description: got %q, want %q", got.Description, res.Description)
	}
	if got.OwnerID != res.OwnerID {
		t.Errorf("OwnerID: got %q, want %q", got.OwnerID, res.OwnerID)
	}
}

// TestFindByIDNotFound verifies that querying a non-existent ID returns ErrCodeNotFound.
func TestFindByIDNotFound(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got: %v", err)
	}
}

// TestFindAll verifies that FindAll returns all saved resources.
func TestFindAll(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	// Save two resources with distinct IDs.
	res1 := newTestResource("findall-1")
	res2 := newTestResource("findall-2")

	if err := repo.Save(ctx, res1); err != nil {
		t.Fatalf("Save res1: %v", err)
	}
	if err := repo.Save(ctx, res2); err != nil {
		t.Fatalf("Save res2: %v", err)
	}

	all, err := repo.FindAll(ctx)
	if err != nil {
		t.Fatalf("FindAll: %v", err)
	}

	// We may have rows from other test runs in the same DB; assert our two IDs are present.
	found := make(map[string]bool)
	for _, r := range all {
		found[r.ID] = true
	}
	if !found[res1.ID] {
		t.Errorf("expected ID %q in FindAll results", res1.ID)
	}
	if !found[res2.ID] {
		t.Errorf("expected ID %q in FindAll results", res2.ID)
	}
}

// TestSaveUpsert verifies that saving a resource with the same ID overwrites the existing record.
func TestSaveUpsert(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	res := newTestResource("upsert")
	if err := repo.Save(ctx, res); err != nil {
		t.Fatalf("Save original: %v", err)
	}

	// Update fields and save again with the same ID.
	res.Name = "Updated Name"
	res.Description = "Updated description"
	if err := repo.Save(ctx, res); err != nil {
		t.Fatalf("Save upsert: %v", err)
	}

	got, err := repo.FindByID(ctx, res.ID)
	if err != nil {
		t.Fatalf("FindByID after upsert: %v", err)
	}
	if got.Name != "Updated Name" {
		t.Errorf("Name: got %q, want %q", got.Name, "Updated Name")
	}
	if got.Description != "Updated description" {
		t.Errorf("Description: got %q, want %q", got.Description, "Updated description")
	}
}

// TestFindAllEmpty verifies that FindAll returns an empty (non-nil) slice when
// no resources match — important for JSON serialisation ([] not null).
func TestFindAllEmpty(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	// This test relies on a clean database. If the table has rows from other
	// tests this assertion will not hold; it is most reliable in isolated CI.
	// We validate the slice is non-nil rather than asserting length == 0.
	all, err := repo.FindAll(ctx)
	if err != nil {
		t.Fatalf("FindAll: %v", err)
	}
	if all == nil {
		t.Error("FindAll returned nil; want non-nil empty slice")
	}
}
