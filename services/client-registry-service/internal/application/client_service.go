package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"golang.org/x/crypto/bcrypt"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

// ClientService handles OAuth client management operations.
type ClientService struct {
	repo       domain.ClientRepository
	bcryptCost int
}

// NewClientService creates a ClientService using bcrypt.DefaultCost for secret hashing.
func NewClientService(repo domain.ClientRepository) *ClientService {
	return &ClientService{repo: repo, bcryptCost: bcrypt.DefaultCost}
}

// NewClientServiceWithCost creates a ClientService with a custom bcrypt cost.
// Use bcrypt.MinCost in tests to avoid paying the full bcrypt work factor on every
// CreateClient call. Returns an error if cost is outside [bcrypt.MinCost, bcrypt.MaxCost].
func NewClientServiceWithCost(repo domain.ClientRepository, cost int) (*ClientService, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest,
			fmt.Sprintf("bcrypt cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost))
	}
	return &ClientService{repo: repo, bcryptCost: cost}, nil
}

// validateCreateRequest checks that a CreateClientRequest contains the required fields.
func validateCreateRequest(req domain.CreateClientRequest) error {
	if req.Name == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "name is required")
	}
	if len(req.GrantTypes) == 0 {
		return apperrors.New(apperrors.ErrCodeBadRequest, "at least one grant type is required")
	}
	if slices.Contains(req.GrantTypes, "") {
		return apperrors.New(apperrors.ErrCodeBadRequest, "grant type must not be blank")
	}
	return nil
}

// CreateClient registers a new OAuth client. It validates the request, generates
// a cryptographically random client ID and secret, bcrypt-hashes the secret, and
// persists the client. The plain-text secret is returned once and is not recoverable.
func (s *ClientService) CreateClient(ctx context.Context, req domain.CreateClientRequest) (*domain.CreateClientResponse, error) {
	if err := validateCreateRequest(req); err != nil {
		return nil, err
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
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), s.bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash client secret: %w", err)
	}

	now := time.Now()
	client := &domain.OAuthClient{
		ID:           id,
		Secret:       string(hash),
		Name:         req.Name,
		Scopes:       req.Scopes,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   req.GrantTypes,
		CreatedAt:    now,
		UpdatedAt:    now,
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

// GetClient returns the metadata for the client with the given ID.
// Returns an ErrCodeNotFound error if no client exists with that ID.
func (s *ClientService) GetClient(ctx context.Context, id string) (*domain.GetClientResponse, error) {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("fetching client: %w", err)
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

// ValidateClient checks whether the provided client credentials are valid.
// It returns Valid=false (no error) when the client does not exist or the secret
// is wrong, so callers cannot distinguish the two cases (avoids client-ID enumeration).
// Non-not-found repository errors are propagated as errors rather than Valid=false.
func (s *ClientService) ValidateClient(ctx context.Context, req domain.ValidateClientRequest) (*domain.ValidateClientResponse, error) {
	// Reject empty secrets immediately — bcrypt comparison would always fail anyway,
	// but short-circuiting avoids unnecessary work and locks the contract explicitly.
	if req.ClientSecret == "" {
		return &domain.ValidateClientResponse{Valid: false}, nil
	}

	client, err := s.repo.FindByID(ctx, req.ClientID)
	if err != nil {
		if apperrors.IsNotFound(err) {
			return &domain.ValidateClientResponse{Valid: false}, nil
		}
		return nil, fmt.Errorf("looking up client: %w", err)
	}

	// bcrypt comparison is constant-time and handles the hashed secret stored in persistence.
	if err := bcrypt.CompareHashAndPassword([]byte(client.Secret), []byte(req.ClientSecret)); err != nil {
		return &domain.ValidateClientResponse{Valid: false}, nil
	}
	return &domain.ValidateClientResponse{Valid: client.Active}, nil
}

// ListClients returns metadata for all registered clients. The returned slice
// is never nil; an empty repository returns an empty slice.
func (s *ClientService) ListClients(ctx context.Context) ([]*domain.GetClientResponse, error) {
	clients, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing clients: %w", err)
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

// DeleteClient removes the client with the given ID from the repository.
// Returns an ErrCodeNotFound error if no client exists with that ID.
func (s *ClientService) DeleteClient(ctx context.Context, id string) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("deleting client %s: %w", id, err)
	}
	return nil
}

// generateHex returns a hex-encoded string of n cryptographically random bytes
// sourced from crypto/rand. The result is 2n characters long.
func generateHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
