//go:build unit

package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/outbound/sqlite"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

// newTestRepo opens a fresh, uniquely-named SQLite file under t.TempDir() so
// every test gets its own isolated database — no shared state, no
// TEST_DATABASE_URL, no external service required.
func newTestRepo(t *testing.T) *sqlite.ClientRepository {
	t.Helper()
	ctx := context.Background()

	dsn := "file:" + filepath.Join(t.TempDir(), "client-registry.db")

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening migration connection: %v", err)
	}
	if err := sqlite.RunMigrations(ctx, db); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing migration connection: %v", err)
	}

	repo, err := sqlite.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	return repo
}

func sampleClient(id string) *domain.OAuthClient {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &domain.OAuthClient{
		ID:                          id,
		Secret:                      "s3cr3t",
		Name:                        "Test Client " + id,
		Type:                        domain.ClientTypeConfidential,
		ActorType:                   domain.ActorTypeService,
		Scopes:                      []string{"read", "write"},
		GrantTypes:                  []string{"client_credentials"},
		RedirectURIs:                []string{"https://example.com/callback"},
		TokenEndpointAuthMethod:     "client_secret_basic",
		RegistrationAccessTokenHash: "",
		Active:                      true,
		CreatedAt:                   now,
		UpdatedAt:                   now,
	}
}

func TestClientRepository_SaveAndFindByID(t *testing.T) {
	// Arrange
	repo := newTestRepo(t)
	ctx := context.Background()
	client := sampleClient("save-find-1")

	// Act
	if err := repo.Save(ctx, client); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := repo.FindByID(ctx, client.ID)

	// Assert
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ID != client.ID {
		t.Errorf("ID: want %q, got %q", client.ID, got.ID)
	}
	if got.Name != client.Name {
		t.Errorf("Name: want %q, got %q", client.Name, got.Name)
	}
	if got.Type != client.Type {
		t.Errorf("Type: want %q, got %q", client.Type, got.Type)
	}
	if got.ActorType != client.ActorType {
		t.Errorf("ActorType: want %q, got %q", client.ActorType, got.ActorType)
	}
	if !got.CreatedAt.Equal(client.CreatedAt) {
		t.Errorf("CreatedAt: want %v, got %v", client.CreatedAt, got.CreatedAt)
	}
}

func TestClientRepository_Save_Conflict(t *testing.T) {
	// Arrange
	repo := newTestRepo(t)
	ctx := context.Background()
	client := sampleClient("save-conflict-1")
	if err := repo.Save(ctx, client); err != nil {
		t.Fatalf("first Save: %v", err)
	}

	// Act
	err := repo.Save(ctx, client)

	// Assert
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}
	if !apperrors.IsConflict(err) {
		t.Errorf("expected ErrCodeConflict, got %v", err)
	}
}

func TestClientRepository_FindByID_NotFound(t *testing.T) {
	// Arrange
	repo := newTestRepo(t)
	ctx := context.Background()

	// Act
	_, err := repo.FindByID(ctx, "does-not-exist")

	// Assert
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestClientRepository_Update(t *testing.T) {
	// Arrange
	repo := newTestRepo(t)
	ctx := context.Background()
	client := sampleClient("update-1")
	if err := repo.Save(ctx, client); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	client.Name = "Updated Name"
	client.UpdatedAt = time.Now().UTC().Truncate(time.Millisecond)
	if err := repo.Update(ctx, client); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := repo.FindByID(ctx, client.ID)

	// Assert
	if err != nil {
		t.Fatalf("FindByID after update: %v", err)
	}
	if got.Name != "Updated Name" {
		t.Errorf("Name: want %q, got %q", "Updated Name", got.Name)
	}
}

func TestClientRepository_Update_ReplacesRelated(t *testing.T) {
	// Arrange
	repo := newTestRepo(t)
	ctx := context.Background()
	client := sampleClient("update-related-1")
	if err := repo.Save(ctx, client); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	client.Scopes = []string{"admin"}
	client.GrantTypes = []string{"authorization_code"}
	client.RedirectURIs = []string{"https://other.example.com/callback"}
	client.UpdatedAt = time.Now().UTC().Truncate(time.Millisecond)
	if err := repo.Update(ctx, client); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := repo.FindByID(ctx, client.ID)

	// Assert
	if err != nil {
		t.Fatalf("FindByID after update: %v", err)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "admin" {
		t.Errorf("Scopes: want [admin], got %v", got.Scopes)
	}
	if len(got.GrantTypes) != 1 || got.GrantTypes[0] != "authorization_code" {
		t.Errorf("GrantTypes: want [authorization_code], got %v", got.GrantTypes)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://other.example.com/callback" {
		t.Errorf("RedirectURIs: want [https://other.example.com/callback], got %v", got.RedirectURIs)
	}
}

func TestClientRepository_Update_NotFound(t *testing.T) {
	// Arrange
	repo := newTestRepo(t)
	ctx := context.Background()
	client := sampleClient("update-missing-1")

	// Act
	err := repo.Update(ctx, client)

	// Assert
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestClientRepository_Delete(t *testing.T) {
	// Arrange
	repo := newTestRepo(t)
	ctx := context.Background()
	client := sampleClient("delete-1")
	if err := repo.Save(ctx, client); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	if err := repo.Delete(ctx, client.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := repo.FindByID(ctx, client.ID)

	// Assert
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected not-found after delete, got %v", err)
	}
}

func TestClientRepository_Delete_NotFound(t *testing.T) {
	// Arrange
	repo := newTestRepo(t)
	ctx := context.Background()

	// Act
	err := repo.Delete(ctx, "delete-missing-1")

	// Assert
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestClientRepository_Delete_CascadesRelatedRows(t *testing.T) {
	// Arrange — this exercises the ON DELETE CASCADE + foreign_keys pragma path,
	// which is SQLite-specific behavior the postgres adapter doesn't need to prove
	// since postgres enables foreign key enforcement by default.
	repo := newTestRepo(t)
	ctx := context.Background()
	client := sampleClient("delete-cascade-1")
	if err := repo.Save(ctx, client); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	if err := repo.Delete(ctx, client.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Assert — re-creating a client with the same ID must not collide with
	// orphaned join-table rows from the deleted client.
	if err := repo.Save(ctx, sampleClient(client.ID)); err != nil {
		t.Fatalf("Save after delete: %v", err)
	}
	got, err := repo.FindByID(ctx, client.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if len(got.Scopes) != len(client.Scopes) {
		t.Errorf("Scopes: want %d entries (no leftover rows from the deleted client), got %d", len(client.Scopes), len(got.Scopes))
	}
}

func TestClientRepository_List(t *testing.T) {
	// Arrange
	repo := newTestRepo(t)
	ctx := context.Background()
	clients := []*domain.OAuthClient{
		sampleClient("list-1"),
		sampleClient("list-2"),
		sampleClient("list-3"),
	}
	for _, c := range clients {
		if err := repo.Save(ctx, c); err != nil {
			t.Fatalf("Save %q: %v", c.ID, err)
		}
	}

	// Act
	all, err := repo.List(ctx)

	// Assert
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := 0
	for _, c := range all {
		for _, want := range clients {
			if c.ID == want.ID {
				found++
			}
		}
	}
	if found != len(clients) {
		t.Errorf("List: wanted %d saved clients in result, found %d", len(clients), found)
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

	// Act — run migrations twice.
	if err := sqlite.RunMigrations(ctx, db); err != nil {
		t.Fatalf("first RunMigrations: %v", err)
	}
	err = sqlite.RunMigrations(ctx, db)

	// Assert — second run must be a no-op, not an error from re-creating tables.
	if err != nil {
		t.Fatalf("second RunMigrations should be a no-op, got error: %v", err)
	}
}

func TestConnect_AppliesForeignKeyPragma(t *testing.T) {
	// Arrange
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "pragma-check.db")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening migration connection: %v", err)
	}
	if err := sqlite.RunMigrations(ctx, db); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing migration connection: %v", err)
	}
	repo, err := sqlite.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	client := sampleClient("fk-pragma-1")
	if err := repo.Save(ctx, client); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	err = repo.Delete(ctx, client.ID)

	// Assert — if foreign_keys were off, this would still succeed but leave
	// orphaned join-table rows instead of cascading; verified indirectly via
	// TestClientRepository_Delete_CascadesRelatedRows above. Here we only
	// confirm Delete itself doesn't fail with the pragma enabled.
	if err != nil {
		t.Fatalf("Delete with foreign_keys pragma enabled: %v", err)
	}
}

// TestClientRepository_SaveAndFindByID_PersistsJWKSURI covers the RFC 7591
// §2 jwks_uri registration field (ADR-0023) added on top of the base
// schema this adapter's other tests exercise.
func TestClientRepository_SaveAndFindByID_PersistsJWKSURI(t *testing.T) {
	// Arrange
	repo := newTestRepo(t)
	ctx := context.Background()
	client := sampleClient("jwks-uri-1")
	client.JWKSURI = "https://client.example.com/.well-known/jwks.json"

	// Act
	if err := repo.Save(ctx, client); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := repo.FindByID(ctx, client.ID)

	// Assert
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.JWKSURI != client.JWKSURI {
		t.Errorf("JWKSURI: want %q, got %q", client.JWKSURI, got.JWKSURI)
	}
}

func TestClientRepository_List_IncludesJWKSURI(t *testing.T) {
	// Arrange
	repo := newTestRepo(t)
	ctx := context.Background()
	client := sampleClient("jwks-uri-list-1")
	client.JWKSURI = "https://client.example.com/.well-known/jwks.json"
	if err := repo.Save(ctx, client); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	clients, err := repo.List(ctx)

	// Assert
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var found bool
	for _, c := range clients {
		if c.ID == client.ID {
			found = true
			if c.JWKSURI != client.JWKSURI {
				t.Errorf("JWKSURI: want %q, got %q", client.JWKSURI, c.JWKSURI)
			}
		}
	}
	if !found {
		t.Fatalf("client %q not found in List result", client.ID)
	}
}
