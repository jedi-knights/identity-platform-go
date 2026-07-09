package domain

// GrantType represents an OAuth2 grant type.
type GrantType string

const (
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	// GrantTypeTokenExchange is the RFC 8693 §2.1 token-exchange grant
	// per ADR-0016. Used for A2A delegation, agent-on-behalf-of-human
	// flows, and service-to-agent fan-out — every case where one
	// principal needs to act for another while preserving both
	// identities in the issued token's act chain.
	GrantTypeTokenExchange GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	// GrantTypeDeviceCode is the RFC 8628 §3.4 device authorization grant
	// per ADR-0022. Used by browserless or input-constrained clients (CLIs,
	// IoT) that obtained a device_code from POST /device_authorization and
	// are polling the token endpoint while a user approves the request on
	// a separate, browser-capable device.
	GrantTypeDeviceCode GrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

// RFC 8693 token type URN values. Initially only the access_token URN
// is supported on both input and output — the platform issues JWTs and
// validates JWTs minted by itself. Other URNs (ID-token, JWT, SAML 2.0,
// etc.) are rejected with invalid_request so the supported surface is
// explicit at the wire.
const (
	TokenTypeURNAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeURNIDToken     = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeURNJWT         = "urn:ietf:params:oauth:token-type:jwt"
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

	// DeviceCode is the RFC 8628 §3.4 device_code form parameter, populated
	// by the HTTP layer only when GrantType == GrantTypeDeviceCode; ignored
	// by every other strategy.
	DeviceCode string

	// Token-exchange (RFC 8693 §2.1) parameters. Populated by the HTTP
	// layer only when GrantType == GrantTypeTokenExchange; ignored by
	// every other strategy. SubjectToken is the JWT whose identity the
	// new token represents; ActorToken (optional) identifies the
	// principal acting on the subject's behalf. Audience and
	// RequestedTokenType are the optional RFC 8693 fields for narrowing
	// the target resource server and the desired output token shape.
	SubjectToken       string
	SubjectTokenType   string
	ActorToken         string
	ActorTokenType     string
	Audience           []string
	RequestedTokenType string

	// AuthorizationDetails is the RFC 9396 §2 parsed array, populated
	// by the HTTP layer when the caller supplies the
	// `authorization_details` form parameter. Nil when the parameter
	// was absent; strategies that issue tokens propagate the slice
	// onto the resulting domain.Token unchanged.
	AuthorizationDetails []AuthorizationDetail
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

	// IssuedTokenType is the RFC 8693 §2.2.1 echo of the issued token
	// type URN. Omitted from non-token-exchange responses so the wire
	// shape for client_credentials / authorization_code / refresh_token
	// is unchanged — RFC 8693 requires the field only on the
	// token-exchange response.
	IssuedTokenType string `json:"issued_token_type,omitempty"`

	// ActorType, AgentID, and Subject are populated by the strategy for
	// audit emission per ADR-0015. They are not serialised on the
	// /oauth/token response — the access token itself carries the
	// authoritative values. Marked json:"-" so they stay strictly
	// server-internal.
	ActorType ActorType `json:"-"`
	AgentID   string    `json:"-"`
	Subject   string    `json:"-"`
}
