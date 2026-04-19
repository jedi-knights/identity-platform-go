//go:build unit

package memory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func TestClientRepository_FindByID_Found(t *testing.T) {
	repo := memory.NewClientRepository([]*domain.Client{testClient()})

	got, err := repo.FindByID(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "client-1" {
		t.Errorf("ID = %q, want %q", got.ID, "client-1")
	}
}

func TestClientRepository_FindByID_NotFound(t *testing.T) {
	repo := memory.NewClientRepository(nil)

	_, err := repo.FindByID(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, memory.ErrClientNotFound) {
		t.Errorf("expected ErrClientNotFound, got: %v", err)
	}
}

func TestClientRepository_Save_OverwritesExisting(t *testing.T) {
	repo := memory.NewClientRepository([]*domain.Client{testClient()})

	updated := &domain.Client{ID: "client-1", Secret: "new-secret", Name: "Updated"}
	if err := repo.Save(context.Background(), updated); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindByID(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("FindByID after Save: %v", err)
	}
	if got.Name != "Updated" {
		t.Errorf("Name = %q, want %q", got.Name, "Updated")
	}
}

func TestClientRepository_Save_NewEntry(t *testing.T) {
	repo := memory.NewClientRepository(nil)

	c := &domain.Client{ID: "new-client", Secret: "s", Name: "New"}
	if err := repo.Save(context.Background(), c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindByID(context.Background(), "new-client")
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ID != "new-client" {
		t.Errorf("ID = %q, want %q", got.ID, "new-client")
	}
}
