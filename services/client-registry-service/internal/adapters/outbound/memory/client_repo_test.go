package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

func sampleClient(id string) *domain.OAuthClient {
	return &domain.OAuthClient{
		ID:           id,
		Secret:       "hash",
		Name:         "Test Client",
		Scopes:       []string{"read"},
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"client_credentials"},
		Active:       true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

// TestFindByID_ReturnsCopy_StructField verifies that mutating a struct field on
// the returned pointer does not corrupt the in-memory store.
func TestFindByID_ReturnsCopy_StructField(t *testing.T) {
	repo := memory.NewClientRepository()
	if err := repo.Save(context.Background(), sampleClient("c1")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindByID(context.Background(), "c1")
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	got.Name = "mutated"

	refetched, err := repo.FindByID(context.Background(), "c1")
	if err != nil {
		t.Fatalf("second FindByID: %v", err)
	}
	if refetched.Name == "mutated" {
		t.Error("FindByID returned a pointer into the store; struct mutation corrupted stored state")
	}
}

// TestFindByID_ReturnsCopy_SliceElement verifies that mutating a slice element on
// the returned pointer does not corrupt the in-memory store (detects shared backing array).
func TestFindByID_ReturnsCopy_SliceElement(t *testing.T) {
	repo := memory.NewClientRepository()
	if err := repo.Save(context.Background(), sampleClient("c1s")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindByID(context.Background(), "c1s")
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if len(got.Scopes) == 0 {
		t.Skip("no scopes to mutate")
	}
	got.Scopes[0] = "mutated-scope"

	refetched, err := repo.FindByID(context.Background(), "c1s")
	if err != nil {
		t.Fatalf("second FindByID: %v", err)
	}
	if len(refetched.Scopes) > 0 && refetched.Scopes[0] == "mutated-scope" {
		t.Error("FindByID shares Scopes backing array with the store; slice element mutation corrupted stored state")
	}
}

// TestList_ReturnsCopy_StructField verifies that mutating a struct field on a pointer
// returned by List does not corrupt the in-memory store.
func TestList_ReturnsCopy_StructField(t *testing.T) {
	repo := memory.NewClientRepository()
	if err := repo.Save(context.Background(), sampleClient("c2")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	list, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) == 0 {
		t.Fatal("expected at least one client in list")
	}
	list[0].Name = "mutated"

	refetched, err := repo.FindByID(context.Background(), "c2")
	if err != nil {
		t.Fatalf("FindByID after List mutation: %v", err)
	}
	if refetched.Name == "mutated" {
		t.Error("List returned a pointer into the store; struct mutation corrupted stored state")
	}
}

// TestList_ReturnsCopy_SliceElement verifies that mutating a slice element on a pointer
// returned by List does not corrupt the in-memory store (detects shared backing array).
func TestList_ReturnsCopy_SliceElement(t *testing.T) {
	repo := memory.NewClientRepository()
	if err := repo.Save(context.Background(), sampleClient("c2s")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	list := listFirstScopes(t, repo)
	if len(list) == 0 {
		t.Skip("no scopes to mutate")
	}
	list[0] = "mutated-scope"

	refetched, err := repo.FindByID(context.Background(), "c2s")
	if err != nil {
		t.Fatalf("FindByID after slice mutation: %v", err)
	}
	if len(refetched.Scopes) > 0 && refetched.Scopes[0] == "mutated-scope" {
		t.Error("List shares Scopes backing array with the store; slice element mutation corrupted stored state")
	}
}

// listFirstScopes returns the Scopes slice of the first client returned by List.
func listFirstScopes(t *testing.T, repo *memory.ClientRepository) []string {
	t.Helper()
	list, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) == 0 {
		return nil
	}
	return list[0].Scopes
}

// TestSave_MutationAfterSaveDoesNotCorruptStore verifies that mutating the pointer
// passed to Save after the call does not corrupt the stored entry.
func TestSave_MutationAfterSaveDoesNotCorruptStore(t *testing.T) {
	repo := memory.NewClientRepository()
	c := sampleClient("c3")
	if err := repo.Save(context.Background(), c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Mutate caller's pointer after Save returns.
	c.Name = "mutated after save"
	if len(c.Scopes) > 0 {
		c.Scopes[0] = "mutated-scope"
	}

	got, err := repo.FindByID(context.Background(), "c3")
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Name == "mutated after save" {
		t.Error("Save stored a pointer alias; struct mutation after Save corrupted stored state")
	}
	if len(got.Scopes) > 0 && got.Scopes[0] == "mutated-scope" {
		t.Error("Save stored a pointer alias; slice element mutation after Save corrupted stored state")
	}
}

// TestSave_DuplicateID_ReturnsConflict verifies that saving a client with an
// already-registered ID returns an ErrCodeConflict error.
func TestSave_DuplicateID_ReturnsConflict(t *testing.T) {
	repo := memory.NewClientRepository()
	if err := repo.Save(context.Background(), sampleClient("dup")); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	err := repo.Save(context.Background(), sampleClient("dup"))
	if err == nil {
		t.Fatal("expected conflict error on duplicate ID, got nil")
	}
	var ae *apperrors.AppError
	if !errors.As(err, &ae) || ae.Code() != apperrors.ErrCodeConflict {
		t.Errorf("expected ErrCodeConflict, got %v", err)
	}
}

// TestUpdate_Success verifies that Update persists the new value and is retrievable.
func TestUpdate_Success(t *testing.T) {
	repo := memory.NewClientRepository()
	if err := repo.Save(context.Background(), sampleClient("u1")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	updated := sampleClient("u1")
	updated.Name = "Updated Name"
	updated.Scopes = []string{"read", "write"}
	if err := repo.Update(context.Background(), updated); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := repo.FindByID(context.Background(), "u1")
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Name != "Updated Name" {
		t.Errorf("got name %q, want %q", got.Name, "Updated Name")
	}
}

// TestUpdate_MutationAfterUpdateDoesNotCorruptStore verifies copy-on-write semantics for Update.
func TestUpdate_MutationAfterUpdateDoesNotCorruptStore(t *testing.T) {
	repo := memory.NewClientRepository()
	if err := repo.Save(context.Background(), sampleClient("u2")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	u := sampleClient("u2")
	u.Name = "Before Mutation"
	if err := repo.Update(context.Background(), u); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Mutate the caller's pointer after Update returns.
	u.Name = "After Mutation"

	got, err := repo.FindByID(context.Background(), "u2")
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Name == "After Mutation" {
		t.Error("Update stored a pointer alias; mutation after Update corrupted stored state")
	}
}

// TestUpdate_NotFound_ReturnsError verifies that updating a non-existent client
// returns an ErrCodeNotFound error.
func TestUpdate_NotFound_ReturnsError(t *testing.T) {
	repo := memory.NewClientRepository()
	err := repo.Update(context.Background(), sampleClient("ghost"))
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	var ae *apperrors.AppError
	if !errors.As(err, &ae) || ae.Code() != apperrors.ErrCodeNotFound {
		t.Errorf("expected ErrCodeNotFound, got %v", err)
	}
}

// TestDelete_Success verifies that a deleted client is no longer retrievable.
func TestDelete_Success(t *testing.T) {
	repo := memory.NewClientRepository()
	if err := repo.Save(context.Background(), sampleClient("d1")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := repo.Delete(context.Background(), "d1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := repo.FindByID(context.Background(), "d1"); err == nil {
		t.Error("expected not-found error after Delete, got nil")
	}
}

// TestDelete_NotFound_ReturnsError verifies that deleting a non-existent client
// returns an ErrCodeNotFound error.
func TestDelete_NotFound_ReturnsError(t *testing.T) {
	repo := memory.NewClientRepository()
	err := repo.Delete(context.Background(), "ghost")
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	var ae *apperrors.AppError
	if !errors.As(err, &ae) || ae.Code() != apperrors.ErrCodeNotFound {
		t.Errorf("expected ErrCodeNotFound, got %v", err)
	}
}

// TestList_Empty_ReturnsNonNilSlice verifies that List on an empty repo returns []
// (not nil) so JSON serialisation produces [] rather than null.
func TestList_Empty_ReturnsNonNilSlice(t *testing.T) {
	repo := memory.NewClientRepository()
	result, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil empty slice, got nil")
	}
	if len(result) != 0 {
		t.Errorf("expected 0 entries, got %d", len(result))
	}
}
