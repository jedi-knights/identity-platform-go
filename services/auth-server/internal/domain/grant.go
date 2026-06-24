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
	// RefreshToken is the raw refresh token value presented by the client
	// during the refresh_token grant (RFC 6749 §6).
	RefreshToken string
}

// GrantResponse contains the issued token information.
type GrantResponse struct {
	AccessToken string `json:"access_token"`
	// IDToken is the OIDC ID token (OIDC Core §2) issued when the granted
	// scopes include "openid". Empty + omitempty when OIDC mode is not active,
	// matching the OAuth-only response shape clients see today.
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}
