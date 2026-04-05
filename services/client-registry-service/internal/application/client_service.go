package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

// ClientService handles OAuth client management operations.
type ClientService struct {
	repo domain.ClientRepository
}

func NewClientService(repo domain.ClientRepository) *ClientService {
	return &ClientService{repo: repo}
}

func (s *ClientService) CreateClient(ctx context.Context, req domain.CreateClientRequest) (*domain.CreateClientResponse, error) {
	if req.Name == "" {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "name is required")
	}
	if len(req.GrantTypes) == 0 {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "at least one grant type is required")
	}

	id, err := generateHex(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client ID: %w", err)
	}

	secret, err := generateHex(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %w", err)
	}

	// Hash the secret before storing so plain-text credentials are never persisted.
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash client secret: %w", err)
	}

	client := &domain.OAuthClient{
		ID:           id,
		Secret:       string(hash),
		Name:         req.Name,
		Scopes:       req.Scopes,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   req.GrantTypes,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Active:       true,
	}

	if err := s.repo.Save(ctx, client); err != nil {
		return nil, fmt.Errorf("failed to save client: %w", err)
	}

	// Return the plain-text secret once — it will not be recoverable from storage.
	return &domain.CreateClientResponse{
		ClientID:     client.ID,
		ClientSecret: secret,
		Name:         client.Name,
		Scopes:       client.Scopes,
		RedirectURIs: client.RedirectURIs,
		GrantTypes:   client.GrantTypes,
	}, nil
}

func (s *ClientService) GetClient(ctx context.Context, id string) (*domain.GetClientResponse, error) {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return &domain.GetClientResponse{
		ClientID:     client.ID,
		Name:         client.Name,
		Scopes:       client.Scopes,
		RedirectURIs: client.RedirectURIs,
		GrantTypes:   client.GrantTypes,
		Active:       client.Active,
	}, nil
}

func (s *ClientService) ValidateClient(ctx context.Context, req domain.ValidateClientRequest) (*domain.ValidateClientResponse, error) {
	client, err := s.repo.FindByID(ctx, req.ClientID)
	if err != nil {
		return &domain.ValidateClientResponse{Valid: false}, nil
	}

	// bcrypt comparison is constant-time and handles the hashed secret stored in persistence.
	if err := bcrypt.CompareHashAndPassword([]byte(client.Secret), []byte(req.ClientSecret)); err != nil {
		return &domain.ValidateClientResponse{Valid: false}, nil
	}
	return &domain.ValidateClientResponse{Valid: client.Active}, nil
}

func (s *ClientService) ListClients(ctx context.Context) ([]*domain.GetClientResponse, error) {
	clients, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*domain.GetClientResponse, 0, len(clients))
	for _, c := range clients {
		result = append(result, &domain.GetClientResponse{
			ClientID:     c.ID,
			Name:         c.Name,
			Scopes:       c.Scopes,
			RedirectURIs: c.RedirectURIs,
			GrantTypes:   c.GrantTypes,
			Active:       c.Active,
		})
	}
	return result, nil
}

func (s *ClientService) DeleteClient(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}

func generateHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
