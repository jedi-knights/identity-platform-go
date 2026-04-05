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

// CreateResourceRequest holds input for creating a resource.
type CreateResourceRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	OwnerID     string `json:"owner_id"`
}

// ResourceService handles resource CRUD business logic.
type ResourceService struct {
	repo domain.ResourceRepository
}

func NewResourceService(repo domain.ResourceRepository) *ResourceService {
	return &ResourceService{repo: repo}
}

func (s *ResourceService) GetResource(_ context.Context, id string) (*domain.Resource, error) {
	if id == "" {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "resource id is required")
	}
	return s.repo.FindByID(id)
}

func (s *ResourceService) ListResources(_ context.Context) ([]*domain.Resource, error) {
	return s.repo.FindAll()
}

func (s *ResourceService) CreateResource(_ context.Context, req CreateResourceRequest) (*domain.Resource, error) {
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

	if err := s.repo.Save(resource); err != nil {
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
