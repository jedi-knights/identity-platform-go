package domain

import "time"

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
	FindByID(id string) (*OAuthClient, error)
	Save(client *OAuthClient) error
	Update(client *OAuthClient) error
	Delete(id string) error
	List() ([]*OAuthClient, error)
}
