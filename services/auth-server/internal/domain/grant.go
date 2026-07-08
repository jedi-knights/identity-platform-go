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

	// GrantTypeSAML2Bearer is the RFC 7522 §2.1 SAML 2.0 Bearer Assertion
	// Grant per ADR-0026 — a SAML assertion identifying the resource owner
	// is exchanged for an access token. Scoped to the assertion-as-grant
	// use case only; RFC 7522 §2.2 (SAML for client authentication) is not
	// implemented.
	GrantTypeSAML2Bearer GrantType = "urn:ietf:params:oauth:grant-type:saml2-bearer"
)

// ClientAssertionTypeJWTBearer is the RFC 7523 §2.2 client_assertion_type
// value this server accepts (ADR-0023). Any other client_assertion_type
// value (e.g. RFC 7522's SAML2 URN) is not supported — the token endpoint
// falls back to requiring client_secret in that case.
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

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

	// ClientAssertion and ClientAssertionType are the RFC 7523 §2.2
	// JWT-bearer client authentication parameters (ADR-0023). Populated by
	// the HTTP layer for every grant type; a strategy that supports
	// assertion-based auth checks ClientAssertion != "" before falling
	// back to ClientSecret. client_id is still required and is verified
	// against the assertion's iss/sub claims after signature verification
	// — see ADR-0023 "Alternatives Considered" for why client_id is not
	// derived solely from the assertion.
	ClientAssertion     string
	ClientAssertionType string

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

	// DPoPJKT is the RFC 7638 thumbprint of the client's DPoP proof key
	// (ADR-0025), populated by the HTTP layer only when the caller
	// presented a valid `DPoP` header at the token endpoint. Empty for
	// ordinary bearer-token requests. Grant-agnostic — every grant type
	// that issues an access token stamps it onto the resulting
	// domain.Token unchanged, the same way AuthorizationDetails does.
	DPoPJKT string

	// SAMLAssertion is the RFC 7522 §3 raw assertion XML, populated by the
	// HTTP layer only when GrantType == GrantTypeSAML2Bearer (base64url-decoded
	// from the `assertion` form parameter); ignored by every other strategy.
	SAMLAssertion string
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
