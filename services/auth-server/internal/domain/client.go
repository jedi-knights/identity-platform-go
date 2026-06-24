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

// Client represents an OAuth2 client.
type Client struct {
	ID           string
	Secret       string
	Name         string
	Type         ClientType
	Scopes       []string
	RedirectURIs []string
	GrantTypes   []GrantType
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
