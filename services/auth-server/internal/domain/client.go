package domain

// Client represents an OAuth2 client.
type Client struct {
	ID           string
	Secret       string
	Name         string
	Scopes       []string
	RedirectURIs []string
	GrantTypes   []GrantType
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
	FindByID(id string) (*Client, error)
	Save(client *Client) error
}
