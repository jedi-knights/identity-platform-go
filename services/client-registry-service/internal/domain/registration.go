package domain

// RFC 7591 token endpoint auth methods supported by this service. Per
// ADR-0013 §"Validation rules" only these three are valid; "none" forces
// the client to ClientTypePublic and suppresses secret issuance.
const (
	TokenEndpointAuthMethodBasic = "client_secret_basic"
	TokenEndpointAuthMethodPost  = "client_secret_post"
	TokenEndpointAuthMethodNone  = "none"
)

// RegistrationRequest is the RFC 7591 §2 client metadata document.
// Every field is optional on the wire; per-field defaults are documented
// alongside the validation rules in the application layer.
type RegistrationRequest struct {
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	TosURI                  string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
	SoftwareStatement       string   `json:"software_statement,omitempty"`
}

// RegistrationResponse is the RFC 7591 §3.2.1 success response. It
// carries the issued credentials plus the management URI / token for the
// companion RFC 7592 endpoints.
//
// ClientSecret is omitted (omitempty) for public clients per §3.2.1.
// ClientSecretExpiresAt is always 0 (never expires) per the ADR's stance
// on rotation; the field is emitted explicitly so clients can rely on
// its presence.
type RegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RegistrationAccessToken string   `json:"registration_access_token"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope,omitempty"`
}

// RFC 7591 §3.2.2 closed error code set. Internal failures are mapped
// to RegistrationErrorServerError; everything client-facing is one of
// the codes below.
const (
	RegistrationErrorInvalidRedirectURI       = "invalid_redirect_uri"
	RegistrationErrorInvalidClientMetadata    = "invalid_client_metadata"
	RegistrationErrorInvalidSoftwareStatement = "invalid_software_statement"
	RegistrationErrorServerError              = "server_error"
)

// RegistrationError carries a typed RFC 7591 error. The application
// layer returns this directly; the HTTP layer marshals it as JSON with
// the spec's field names (error / error_description).
type RegistrationError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// Error implements the error interface. The string form is the wire
// `error_description` so a wrapped error retains the human-readable
// context for logs and tests.
func (e *RegistrationError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}
