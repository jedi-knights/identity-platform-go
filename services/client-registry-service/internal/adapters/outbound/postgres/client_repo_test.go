//go:build integration

package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/outbound/postgres"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

func newTestRepo(t *testing.T) *postgres.ClientRepository {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping integration tests")
	}

	ctx := context.Background()

	if err := postgres.RunMigrations(dsn); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	repo, err := postgres.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { repo.Close() })

	return repo
}

func sampleClient(id string) *domain.OAuthClient {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &domain.OAuthClient{
		ID:           id,
		Secret:       "s3cr3t",
		Name:         "Test Client " + id,
		Scopes:       []string{"read", "write"},
		GrantTypes:   []string{"client_credentials"},
		RedirectURIs: []string{"https://example.com/callback"},
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func TestClientRepository_SaveAndFindByID(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	client := sampleClient("save-find-1")
	if err := repo.Save(ctx, client); err != nil {
		t.Fatalf("Save: %v", err)
	}
	t.Cleanup(func() { _ = repo.Delete(ctx, client.ID) })

	got, err := repo.FindByID(ctx, client.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ID != client.ID {
		t.Errorf("ID: want %q, got %q", client.ID, got.ID)
	}
	if got.Name != client.Name {
		t.Errorf("Name: want %q, got %q", client.Name, got.Name)
	}
}

func TestClientRepository_Save_Conflict(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	client := sampleClient("save-conflict-1")
	if err := repo.Save(ctx, client); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	t.Cleanup(func() { _ = repo.Delete(ctx, client.ID) })

	err := repo.Save(ctx, client)
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}
	if !apperrors.IsConflict(err) {
		t.Errorf("expected ErrCodeConflict, got %v", err)
	}
}

func TestClientRepository_FindByID_NotFound(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, "does-not-exist")
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestClientRepository_Update(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	client := sampleClient("update-1")
	if err := repo.Save(ctx, client); err != nil {
		t.Fatalf("Save: %v", err)
	}
	t.Cleanup(func() { _ = repo.Delete(ctx, client.ID) })

	client.Name = "Updated Name"
	client.UpdatedAt = time.Now().UTC().Truncate(time.Millisecond)
	if err := repo.Update(ctx, client); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := repo.FindByID(ctx, client.ID)
	if err != nil {
		t.Fatalf("FindByID after update: %v", err)
	}
	if got.Name != "Updated Name" {
		t.Errorf("Name: want %q, got %q", "Updated Name", got.Name)
	}
}

func TestClientRepository_Update_ReplacesRelated(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	client := sampleClient("update-related-1")
	if err := repo.Save(ctx, client); err != nil {
		t.Fatalf("Save: %v", err)
	}
	t.Cleanup(func() { _ = repo.Delete(ctx, client.ID) })

	// Replace all related slices with different values.
	client.Scopes = []string{"admin"}
	client.GrantTypes = []string{"authorization_code"}
	client.RedirectURIs = []string{"https://other.example.com/callback"}
	client.UpdatedAt = time.Now().UTC().Truncate(time.Millisecond)
	if err := repo.Update(ctx, client); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := repo.FindByID(ctx, client.ID)
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
	repo := newTestRepo(t)
	ctx := context.Background()

	client := sampleClient("update-missing-1")
	err := repo.Update(ctx, client)
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestClientRepository_Delete(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	client := sampleClient("delete-1")
	if err := repo.Save(ctx, client); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := repo.Delete(ctx, client.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := repo.FindByID(ctx, client.ID)
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected not-found after delete, got %v", err)
	}
}

func TestClientRepository_Delete_NotFound(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	err := repo.Delete(ctx, "delete-missing-1")
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestClientRepository_List(t *testing.T) {
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
	t.Cleanup(func() {
		for _, c := range clients {
			_ = repo.Delete(ctx, c.ID)
		}
	})

	all, err := repo.List(ctx)
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
