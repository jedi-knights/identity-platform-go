package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/domain"
)

// ResourceService handles resource CRUD business logic.
type ResourceService struct {
	repo domain.ResourceRepository
}

// NewResourceService creates a ResourceService backed by the given repository.
func NewResourceService(repo domain.ResourceRepository) *ResourceService {
	return &ResourceService{repo: repo}
}

// GetResource returns the resource with the given ID.
func (s *ResourceService) GetResource(ctx context.Context, id string) (*domain.Resource, error) {
	if id == "" {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "resource id is required")
	}
	return s.repo.FindByID(ctx, id)
}

// ListResources returns all resources.
func (s *ResourceService) ListResources(ctx context.Context) ([]*domain.Resource, error) {
	return s.repo.FindAll(ctx)
}

// CreateResource creates a new resource from the given request.
func (s *ResourceService) CreateResource(ctx context.Context, req domain.CreateResourceRequest) (*domain.Resource, error) {
	if req.Name == "" {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "name is required")
	}

	id, err := generateResourceID()
	if err != nil {
		return nil, fmt.Errorf("generating resource id: %w", err)
	}

	resource := &domain.Resource{
		ID:          id,
		Name:        req.Name,
		Description: req.Description,
		OwnerID:     req.OwnerID,
		CreatedAt:   time.Now(),
	}

	if err := s.repo.Save(ctx, resource); err != nil {
		return nil, err
	}

	return resource, nil
}

func generateResourceID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating resource id: %w", err)
	}
	return "res-" + hex.EncodeToString(b), nil
}
