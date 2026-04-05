package domain

import (
	"context"
	"time"
)

// OAuthClient represents a registered OAuth2 client.
type OAuthClient struct {
	ID           string
	Secret       string
	Name         string
	Scopes       []string
	RedirectURIs []string
	GrantTypes   []string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Active       bool
}

// ClientRepository defines persistence for OAuth clients.
type ClientRepository interface {
	FindByID(ctx context.Context, id string) (*OAuthClient, error)
	Save(ctx context.Context, client *OAuthClient) error
	Update(ctx context.Context, client *OAuthClient) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]*OAuthClient, error)
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
