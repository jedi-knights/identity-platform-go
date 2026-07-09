package domain

import "context"

// ClientType distinguishes OAuth clients that can safely hold a secret from
// those that cannot. Public clients (SPAs, native apps, MCP connectors in a
// browser tab) authenticate at the token endpoint with PKCE proof of
// possession only; confidential clients additionally present their secret.
//
// Any value other than ClientTypePublic is treated as confidential — see
// Client.IsPublic. This fail-closed default protects existing client records
// stored before the field existed (zero value "") and forward-protects
// against unrecognised values arriving from the client registry.
type ClientType string

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"
)

// ActorType classifies the principal kind a client represents per
// identity-platform-go ADR-0015. Orthogonal to [ClientType] — a confidential
// client may be a service or an agent; a public client may be a user-driven
// SPA or an agent. Empty / unrecognised values are treated as
// [ActorTypeService] at the application boundary (see [Client.ResolvedActorType]).
type ActorType string

const (
	ActorTypeUser    ActorType = "user"
	ActorTypeService ActorType = "service"
	ActorTypeAgent   ActorType = "agent"
)

// Client represents an OAuth2 client.
//
// ActorType (ADR-0015) classifies the principal kind. When ActorType is
// "agent" the client's ID also serves as the agent_id claim on issued
// tokens — agents are registered as OAuth clients in this portfolio, so
// the two identifiers coincide.
type Client struct {
	ID           string
	Secret       string
	Name         string
	Type         ClientType
	ActorType    ActorType
	Scopes       []string
	RedirectURIs []string
	GrantTypes   []GrantType

	// JWKSURI is the RFC 7591 §2 registration field advertising where this
	// client publishes its public signing key(s), for RFC 7523 JWT-bearer
	// client authentication (ADR-0023). Empty means the client has not
	// opted in — Secret remains its only credential at the token endpoint.
	JWKSURI string
}

// ResolvedActorType returns the client's ActorType normalised against the
// recognised enum, defaulting to [ActorTypeService] for empty or
// unrecognised values per ADR-0015's fail-closed rule. Use this when
// emitting tokens or audit events so persisted records that pre-date
// ADR-0015 surface as service rather than as the empty string.
func (c *Client) ResolvedActorType() ActorType {
	if c == nil {
		return ActorTypeService
	}
	switch c.ActorType {
	case ActorTypeUser, ActorTypeAgent:
		return c.ActorType
	default:
		return ActorTypeService
	}
}

// AgentID returns the agent identifier when the client represents an
// agent, and the empty string otherwise. Today this returns Client.ID
// for agents; the indirection lets a future ADR introduce a distinct
// agent_id without changing call sites.
func (c *Client) AgentID() string {
	if c == nil || c.ResolvedActorType() != ActorTypeAgent {
		return ""
	}
	return c.ID
}

// IsPublic reports whether the client is a public client (no secret).
// Only the literal value ClientTypePublic returns true — every other value,
// including the zero value and unrecognised future types, returns false.
func (c *Client) IsPublic() bool {
	return c != nil && c.Type == ClientTypePublic
}

// IsConfidential reports whether the client must authenticate with its
// secret at the token endpoint. The inverse of IsPublic — chosen as the
// fail-closed default so an empty or unrecognised Type does not silently
// downgrade to the public flow's relaxed authentication.
func (c *Client) IsConfidential() bool {
	return !c.IsPublic()
}

func (c *Client) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (c *Client) HasGrantType(gt GrantType) bool {
	for _, g := range c.GrantTypes {
		if g == gt {
			return true
		}
	}
	return false
}

func (c *Client) HasRedirectURI(uri string) bool {
	for _, r := range c.RedirectURIs {
		if r == uri {
			return true
		}
	}
	return false
}

// ClientRepository is the port for client persistence.
type ClientRepository interface {
	FindByID(ctx context.Context, id string) (*Client, error)
	Save(ctx context.Context, client *Client) error
}
