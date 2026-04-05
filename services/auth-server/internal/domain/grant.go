package domain

// GrantType represents an OAuth2 grant type.
type GrantType string

const (
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
)

// GrantRequest contains the parameters for a token grant request.
type GrantRequest struct {
	GrantType    GrantType
	ClientID     string
	ClientSecret string
	Scopes       []string
	Code         string
	CodeVerifier string
	RedirectURI  string
	// Username and Password are used by the authorization_code flow to
	// verify the resource owner's identity against identity-service.
	Username string
	Password string
	// RefreshToken is the raw refresh token value presented by the client
	// during the refresh_token grant (RFC 6749 §6).
	RefreshToken string
}

// GrantResponse contains the issued token information.
type GrantResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}
