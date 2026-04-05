//go:build unit

package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/domain"
)

func TestResourceRepository_FindByID_SeededEntry(t *testing.T) {
	repo := memory.NewResourceRepository()
	ctx := context.Background()

	// "res-1" is seeded in NewResourceRepository.
	got, err := repo.FindByID(ctx, "res-1")
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ID != "res-1" {
		t.Errorf("ID = %q, want %q", got.ID, "res-1")
	}
}

func TestResourceRepository_FindByID_NotFound(t *testing.T) {
	repo := memory.NewResourceRepository()
	ctx := context.Background()

	_, err := repo.FindByID(ctx, "missing")
	if err == nil {
		t.Fatal("expected error for unknown resource, got nil")
	}
	var appErr *apperrors.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected *apperrors.AppError, got: %T %v", err, err)
	}
	if appErr.Code() != apperrors.ErrCodeNotFound {
		t.Errorf("expected ErrCodeNotFound, got: %s", appErr.Code())
	}
}

func TestResourceRepository_FindAll_ReturnsSeeded(t *testing.T) {
	repo := memory.NewResourceRepository()
	ctx := context.Background()

	all, err := repo.FindAll(ctx)
	if err != nil {
		t.Fatalf("FindAll: %v", err)
	}
	if len(all) == 0 {
		t.Error("expected at least one seeded resource, got none")
	}
}

func TestResourceRepository_Save_NewEntry(t *testing.T) {
	repo := memory.NewResourceRepository()
	ctx := context.Background()

	res := &domain.Resource{
		ID:          "res-new",
		Name:        "New Resource",
		Description: "test",
		OwnerID:     "user-2",
		CreatedAt:   time.Now(),
	}
	if err := repo.Save(ctx, res); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindByID(ctx, "res-new")
	if err != nil {
		t.Fatalf("FindByID after Save: %v", err)
	}
	if got.Name != "New Resource" {
		t.Errorf("Name = %q, want %q", got.Name, "New Resource")
	}
}

func TestResourceRepository_Save_OverwritesExisting(t *testing.T) {
	repo := memory.NewResourceRepository()
	ctx := context.Background()

	updated := &domain.Resource{
		ID:          "res-1",
		Name:        "Updated Name",
		Description: "updated",
		OwnerID:     "user-1",
		CreatedAt:   time.Now(),
	}
	if err := repo.Save(ctx, updated); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindByID(ctx, "res-1")
	if err != nil {
		t.Fatalf("FindByID after Save: %v", err)
	}
	if got.Name != "Updated Name" {
		t.Errorf("Name = %q, want %q", got.Name, "Updated Name")
	}
}

// TestResourceRepository_Save_StoresDefensiveCopy verifies that mutating the pointer
// after Save does not corrupt the repository's internal state.
func TestResourceRepository_Save_StoresDefensiveCopy(t *testing.T) {
	repo := memory.NewResourceRepository()
	ctx := context.Background()

	res := &domain.Resource{ID: "res-copy", Name: "original"}
	if err := repo.Save(ctx, res); err != nil {
		t.Fatalf("Save: %v", err)
	}
	res.Name = "mutated after save"

	got, err := repo.FindByID(ctx, "res-copy")
	if err != nil {
		t.Fatalf("FindByID after Save: %v", err)
	}
	if got.Name != "original" {
		t.Errorf("Save stored a raw pointer; caller mutation corrupted the repo: got %q", got.Name)
	}
}

// TestResourceRepository_FindAll_ReturnsCopies verifies that mutating elements returned
// by FindAll does not corrupt the repository's internal state.
func TestResourceRepository_FindAll_ReturnsCopies(t *testing.T) {
	repo := memory.NewResourceRepository()
	ctx := context.Background()

	all, err := repo.FindAll(ctx)
	if err != nil {
		t.Fatalf("FindAll: %v", err)
	}
	for _, r := range all {
		r.Name = "MUTATED"
	}

	again, err := repo.FindAll(ctx)
	if err != nil {
		t.Fatalf("second FindAll: %v", err)
	}
	for _, r := range again {
		if r.Name == "MUTATED" {
			t.Error("FindAll returned raw internal pointers; caller mutation corrupted the repo")
		}
	}
}

// TestResourceRepository_FindByID_ReturnsCopy verifies that mutating the returned
// pointer does not corrupt the repository's internal state.
func TestResourceRepository_FindByID_ReturnsCopy(t *testing.T) {
	repo := memory.NewResourceRepository()
	ctx := context.Background()

	got, err := repo.FindByID(ctx, "res-1")
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}

	// Mutate the returned value.
	got.Name = "MUTATED"

	// Re-fetch and confirm the repo was not affected.
	again, err := repo.FindByID(ctx, "res-1")
	if err != nil {
		t.Fatalf("second FindByID: %v", err)
	}
	if again.Name == "MUTATED" {
		t.Error("FindByID returned a raw internal pointer; mutation corrupted the repository")
	}
}

func TestResourceRepository_FindAll_IncludesSaved(t *testing.T) {
	repo := memory.NewResourceRepository()
	ctx := context.Background()

	res := &domain.Resource{
		ID:          "res-extra",
		Name:        "Extra",
		Description: "extra",
		OwnerID:     "user-3",
		CreatedAt:   time.Now(),
	}
	if err := repo.Save(ctx, res); err != nil {
		t.Fatalf("Save: %v", err)
	}

	all, err := repo.FindAll(ctx)
	if err != nil {
		t.Fatalf("FindAll: %v", err)
	}
	found := false
	for _, r := range all {
		if r.ID == "res-extra" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected saved resource in FindAll results")
	}
}
