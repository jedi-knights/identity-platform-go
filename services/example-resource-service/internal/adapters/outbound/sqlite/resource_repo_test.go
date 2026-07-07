//go:build unit

package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/sqlite"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/domain"
)

// setupRepo opens a fresh, uniquely-named SQLite file under t.TempDir() so
// every test gets its own isolated database — no shared state, no
// TEST_DATABASE_URL, no external service required, and no "may have rows
// from other test runs" caveats like the postgres integration tests carry.
func setupRepo(t *testing.T) *sqlite.ResourceRepository {
	t.Helper()
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "resources.db")

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

	return sqlite.NewResourceRepository(db)
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

func TestResourceRepository_SaveAndFindByID(t *testing.T) {
	// Arrange
	repo := setupRepo(t)
	ctx := context.Background()
	res := newTestResource("save-findbyid")

	// Act
	if err := repo.Save(ctx, res); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := repo.FindByID(ctx, res.ID)

	// Assert
	if err != nil {
		t.Fatalf("FindByID: %v", err)
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
	if !got.CreatedAt.Equal(res.CreatedAt) {
		t.Errorf("CreatedAt: got %v, want %v", got.CreatedAt, res.CreatedAt)
	}
}

func TestResourceRepository_FindByID_NotFound(t *testing.T) {
	// Arrange
	repo := setupRepo(t)
	ctx := context.Background()

	// Act
	_, err := repo.FindByID(ctx, "nonexistent-id")

	// Assert
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got: %v", err)
	}
}

func TestResourceRepository_FindAll(t *testing.T) {
	// Arrange
	repo := setupRepo(t)
	ctx := context.Background()
	res1 := newTestResource("findall-1")
	res2 := newTestResource("findall-2")
	if err := repo.Save(ctx, res1); err != nil {
		t.Fatalf("Save res1: %v", err)
	}
	if err := repo.Save(ctx, res2); err != nil {
		t.Fatalf("Save res2: %v", err)
	}

	// Act
	all, err := repo.FindAll(ctx)

	// Assert
	if err != nil {
		t.Fatalf("FindAll: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("FindAll: want 2 resources, got %d", len(all))
	}
	if all[0].ID != res1.ID || all[1].ID != res2.ID {
		t.Errorf("FindAll: want order [%s, %s], got [%s, %s]", res1.ID, res2.ID, all[0].ID, all[1].ID)
	}
}

func TestResourceRepository_Save_Upsert(t *testing.T) {
	// Arrange
	repo := setupRepo(t)
	ctx := context.Background()
	res := newTestResource("upsert")
	if err := repo.Save(ctx, res); err != nil {
		t.Fatalf("Save original: %v", err)
	}

	// Act
	res.Name = "Updated Name"
	res.Description = "Updated description"
	if err := repo.Save(ctx, res); err != nil {
		t.Fatalf("Save upsert: %v", err)
	}
	got, err := repo.FindByID(ctx, res.ID)

	// Assert
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

func TestResourceRepository_Save_Upsert_PreservesCreatedAt(t *testing.T) {
	// Arrange — postgres's ON CONFLICT DO UPDATE deliberately omits
	// created_at from the SET clause so the original creation time survives
	// an upsert; this SQLite adapter mirrors that.
	repo := setupRepo(t)
	ctx := context.Background()
	res := newTestResource("upsert-created-at")
	if err := repo.Save(ctx, res); err != nil {
		t.Fatalf("Save original: %v", err)
	}

	// Act
	later := &domain.Resource{
		ID:          res.ID,
		Name:        res.Name,
		Description: res.Description,
		OwnerID:     res.OwnerID,
		CreatedAt:   res.CreatedAt.Add(time.Hour),
	}
	if err := repo.Save(ctx, later); err != nil {
		t.Fatalf("Save upsert: %v", err)
	}
	got, err := repo.FindByID(ctx, res.ID)

	// Assert
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if !got.CreatedAt.Equal(res.CreatedAt) {
		t.Errorf("CreatedAt: want unchanged %v, got %v", res.CreatedAt, got.CreatedAt)
	}
}

func TestResourceRepository_FindAll_Empty(t *testing.T) {
	// Arrange
	repo := setupRepo(t)
	ctx := context.Background()

	// Act
	all, err := repo.FindAll(ctx)

	// Assert
	if err != nil {
		t.Fatalf("FindAll: %v", err)
	}
	if all == nil {
		t.Error("FindAll returned nil; want non-nil empty slice")
	}
	if len(all) != 0 {
		t.Errorf("FindAll: want 0 resources, got %d", len(all))
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
