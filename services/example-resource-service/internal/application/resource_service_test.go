package application_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/domain"
)

type mockResourceRepo struct {
	resources map[string]*domain.Resource
}

func newMockResourceRepo() *mockResourceRepo {
	return &mockResourceRepo{resources: make(map[string]*domain.Resource)}
}

func (m *mockResourceRepo) FindByID(_ context.Context, id string) (*domain.Resource, error) {
	r, ok := m.resources[id]
	if !ok {
		return nil, fmt.Errorf("resource not found: %s", id)
	}
	return r, nil
}

func (m *mockResourceRepo) FindAll(_ context.Context) ([]*domain.Resource, error) {
	result := make([]*domain.Resource, 0, len(m.resources))
	for _, r := range m.resources {
		result = append(result, r)
	}
	return result, nil
}

func (m *mockResourceRepo) Save(_ context.Context, r *domain.Resource) error {
	m.resources[r.ID] = r
	return nil
}

func TestResourceService_GetResource_Success(t *testing.T) {
	repo := newMockResourceRepo()
	repo.resources["res-1"] = &domain.Resource{
		ID:        "res-1",
		Name:      "Test Resource",
		OwnerID:   "user-1",
		CreatedAt: time.Now(),
	}

	svc := application.NewResourceService(repo)
	r, err := svc.GetResource(context.Background(), "res-1")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ID != "res-1" {
		t.Errorf("expected id res-1, got %s", r.ID)
	}
}

func TestResourceService_GetResource_EmptyID(t *testing.T) {
	repo := newMockResourceRepo()
	svc := application.NewResourceService(repo)

	_, err := svc.GetResource(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestResourceService_ListResources(t *testing.T) {
	repo := newMockResourceRepo()
	repo.resources["res-1"] = &domain.Resource{ID: "res-1", Name: "A"}
	repo.resources["res-2"] = &domain.Resource{ID: "res-2", Name: "B"}

	svc := application.NewResourceService(repo)
	resources, err := svc.ListResources(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 2 {
		t.Errorf("expected 2 resources, got %d", len(resources))
	}
}

func TestResourceService_CreateResource_Success(t *testing.T) {
	repo := newMockResourceRepo()
	svc := application.NewResourceService(repo)

	r, err := svc.CreateResource(context.Background(), domain.CreateResourceRequest{
		Name:        "My Resource",
		Description: "A test resource",
		OwnerID:     "user-1",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Name != "My Resource" {
		t.Errorf("expected name 'My Resource', got %s", r.Name)
	}
	if r.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestResourceService_CreateResource_EmptyName(t *testing.T) {
	repo := newMockResourceRepo()
	svc := application.NewResourceService(repo)

	_, err := svc.CreateResource(context.Background(), domain.CreateResourceRequest{
		Name: "",
	})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}
