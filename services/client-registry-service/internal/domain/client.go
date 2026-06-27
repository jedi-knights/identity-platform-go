package domain

import (
	"context"
	"time"
)

// ClientType distinguishes OAuth clients that can safely hold a secret from
// those that cannot. Public clients authenticate at the token endpoint with
// PKCE proof of possession only; confidential clients additionally present
// their secret. See ADR-0009 for the wider design.
//
// Any value other than ClientTypePublic is treated as confidential at the
// application boundary — this fail-closed default protects existing client
// records stored before the field existed (zero value "") and forward-
// protects against unrecognised values arriving from the wire.
type ClientType string

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"
)

// ActorType classifies the principal kind a client represents per
// identity-platform-go ADR-0015. It is orthogonal to [ClientType] —
// a confidential client may be a service or an agent; a public client
// may be a user-driven SPA or an agent.
//
// Empty / unrecognised values are treated as ActorTypeService at the
// application boundary so records persisted before ADR-0015 remain
// well-formed.
type ActorType string

const (
	ActorTypeUser    ActorType = "user"
	ActorTypeService ActorType = "service"
	ActorTypeAgent   ActorType = "agent"
)

// OAuthClient represents a registered OAuth2 client.
//
// ActorType (ADR-0015) classifies the principal kind. When ActorType is
// "agent" the client's ID also serves as the agent_id claim on issued
// tokens — there is no separate AgentID field because, in this portfolio,
// agents are registered as OAuth clients and the two identifiers
// coincide.
type OAuthClient struct {
	ID           string
	Secret       string
	Name         string
	Type         ClientType
	ActorType    ActorType
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
// ClientType is optional — absent / empty defaults to "confidential" for
// backwards compatibility with callers that pre-date ADR-0009.
// ActorType is optional — absent / empty defaults to "service" for
// backwards compatibility with callers that pre-date ADR-0015.
type CreateClientRequest struct {
	Name         string   `json:"name"`
	ClientType   string   `json:"client_type,omitempty"`
	ActorType    string   `json:"actor_type,omitempty"`
	Scopes       []string `json:"scopes"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
}

// CreateClientResponse contains the newly created client's credentials.
// ClientSecret is omitted for public clients (no secret to return).
type CreateClientResponse struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Name         string   `json:"name"`
	ClientType   string   `json:"client_type"`
	ActorType    string   `json:"actor_type"`
	Scopes       []string `json:"scopes"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
}

// GetClientResponse contains client details (secret excluded).
type GetClientResponse struct {
	ClientID     string   `json:"client_id"`
	Name         string   `json:"name"`
	ClientType   string   `json:"client_type"`
	ActorType    string   `json:"actor_type"`
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
