package domain

// AuthorizationServerMetadata is the RFC 8414 + OIDC Discovery 1.0 metadata
// document. The field set is the union of both specs; OIDC-only fields are
// omitempty so the RFC 8414 endpoint serves a tighter document when OIDC is
// disabled.
//
// Field ordering follows RFC 8414 §2 for the OAuth fields, then OIDC
// Discovery §3 for the OIDC additions, then the few non-standard fields
// the portfolio advertises (cached via omitempty for forward compatibility
// with ADR-0013 once dynamic client registration ships).
type AuthorizationServerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	// DeviceAuthorizationEndpoint is the RFC 8628 §4 metadata field.
	// Advertised unconditionally, like AuthorizationEndpoint and
	// TokenEndpoint (ADR-0022) — the URL is stable regardless of whether
	// login-ui is wired to actually approve requests.
	DeviceAuthorizationEndpoint               string   `json:"device_authorization_endpoint,omitempty"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint                        string   `json:"revocation_endpoint,omitempty"`
	JWKSURI                                   string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                      string   `json:"registration_endpoint,omitempty"`
	PushedAuthorizationRequestEndpoint        string   `json:"pushed_authorization_request_endpoint,omitempty"`
	ScopesSupported                           []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                    []string `json:"response_types_supported"`
	GrantTypesSupported                       []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported,omitempty"`
	ServiceDocumentation                      string   `json:"service_documentation,omitempty"`
	UILocalesSupported                        []string `json:"ui_locales_supported,omitempty"`

	// AuthorizationDetailsTypesSupported lists the RFC 9396 §10 type
	// discriminators this server understands (ADR-0017). Emitted on
	// both /.well-known endpoints because clients use it to decide
	// whether to opt into the richer parameter.
	AuthorizationDetailsTypesSupported []string `json:"authorization_details_types_supported,omitempty"`

	// OIDC Discovery 1.0 §3 additions. Emitted in the OIDC Discovery
	// document; RFC 8414 §2 tolerates the extras but they convey OIDC
	// semantics, so the RFC 8414 path omits them.
	UserInfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
	EndSessionEndpoint               string   `json:"end_session_endpoint,omitempty"`
	SubjectTypesSupported            []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`
	ClaimTypesSupported              []string `json:"claim_types_supported,omitempty"`
	ResponseModesSupported           []string `json:"response_modes_supported,omitempty"`

	// RequestParameterSupported and friends are pointer-bool so the
	// "false" value is distinguishable from "omitted" — RFC 8414 §2 lets
	// us emit either, and emitting an explicit false is what every major
	// IdP does to telegraph that the feature is intentionally off.
	RequestParameterSupported     *bool `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported  *bool `json:"request_uri_parameter_supported,omitempty"`
	RequireRequestURIRegistration *bool `json:"require_request_uri_registration,omitempty"`
}
