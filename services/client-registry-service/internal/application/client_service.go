package application

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

// ClientService handles OAuth client management operations.
type ClientService struct {
	repo domain.ClientRepository
}

func NewClientService(repo domain.ClientRepository) *ClientService {
	return &ClientService{repo: repo}
}

// CreateClientRequest contains the data required to register a new OAuth client.
type CreateClientRequest struct {
	Name         string   `json:"name"`
	Scopes       []string `json:"scopes"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
}

// CreateClientResponse contains the newly created client's credentials.
type CreateClientResponse struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Name         string   `json:"name"`
	Scopes       []string `json:"scopes"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
}

// GetClientResponse contains client details (secret excluded).
type GetClientResponse struct {
	ClientID     string   `json:"client_id"`
	Name         string   `json:"name"`
	Scopes       []string `json:"scopes"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Active       bool     `json:"active"`
}

// ValidateClientRequest contains credentials to validate.
type ValidateClientRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// ValidateClientResponse reports whether the credentials are valid.
type ValidateClientResponse struct {
	Valid bool `json:"valid"`
}

func (s *ClientService) CreateClient(_ context.Context, req CreateClientRequest) (*CreateClientResponse, error) {
	id, err := generateHex(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client ID: %w", err)
	}

	secret, err := generateHex(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %w", err)
	}

	client := &domain.OAuthClient{
		ID:           id,
		Secret:       secret,
		Name:         req.Name,
		Scopes:       req.Scopes,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   req.GrantTypes,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Active:       true,
	}

	if err := s.repo.Save(client); err != nil {
		return nil, fmt.Errorf("failed to save client: %w", err)
	}

	return &CreateClientResponse{
		ClientID:     client.ID,
		ClientSecret: client.Secret,
		Name:         client.Name,
		Scopes:       client.Scopes,
		RedirectURIs: client.RedirectURIs,
		GrantTypes:   client.GrantTypes,
	}, nil
}

func (s *ClientService) GetClient(_ context.Context, id string) (*GetClientResponse, error) {
	client, err := s.repo.FindByID(id)
	if err != nil {
		return nil, err
	}

	return &GetClientResponse{
		ClientID:     client.ID,
		Name:         client.Name,
		Scopes:       client.Scopes,
		RedirectURIs: client.RedirectURIs,
		GrantTypes:   client.GrantTypes,
		Active:       client.Active,
	}, nil
}

func (s *ClientService) ValidateClient(_ context.Context, req ValidateClientRequest) (*ValidateClientResponse, error) {
	client, err := s.repo.FindByID(req.ClientID)
	if err != nil {
		return &ValidateClientResponse{Valid: false}, nil
	}

	secretMatch := subtle.ConstantTimeCompare([]byte(client.Secret), []byte(req.ClientSecret)) == 1
	return &ValidateClientResponse{Valid: client.Active && secretMatch}, nil
}

func (s *ClientService) ListClients(_ context.Context) ([]*GetClientResponse, error) {
	clients, err := s.repo.List()
	if err != nil {
		return nil, err
	}

	result := make([]*GetClientResponse, 0, len(clients))
	for _, c := range clients {
		result = append(result, &GetClientResponse{
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

func (s *ClientService) DeleteClient(_ context.Context, id string) error {
	return s.repo.Delete(id)
}

func generateHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
