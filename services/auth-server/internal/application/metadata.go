package application

import (
	"strings"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// MetadataBuilder constructs RFC 8414 + OIDC Discovery 1.0 metadata
// documents from running auth-server configuration. The builder is
// stateless and safe for concurrent use — every call recomputes against
// its captured inputs so a config reload only requires reconstructing
// the builder.
type MetadataBuilder struct {
	publicBaseURL        string
	issuer               string
	oidcIssuer           string
	signingAlg           string
	hasJWKS              bool
	hasOIDC              bool
	hasUserInfo          bool
	hasLoginUI           bool
	hasRegistration      bool
	registrationEndpoint string
	serviceDocs          string
	endSessionEndpoint   string
	scopes               []string
}

// MetadataBuilderConfig captures the inputs to [NewMetadataBuilder] so
// the constructor stays small and self-documenting.
type MetadataBuilderConfig struct {
	// PublicBaseURL is the absolute origin clients use to reach
	// auth-server (e.g. "https://auth.example.com"). Trailing slashes
	// are trimmed.
	PublicBaseURL string

	// Issuer is the value reported in the iss claim on access tokens.
	// Used as the OAuth metadata document's issuer field when OIDCIssuer
	// is unset.
	Issuer string

	// OIDCIssuer is the value reported in id_token's iss claim. When
	// non-empty, the OIDC Discovery document advertises this as its
	// issuer; the OAuth document still uses [Issuer].
	OIDCIssuer string

	// SigningAlg is the active JWT signing algorithm ("RS256" or
	// "HS256"). Determines the values surfaced in
	// id_token_signing_alg_values_supported.
	SigningAlg string

	// HasJWKS is true when the JWKS endpoint is wired (RS256 mode).
	HasJWKS bool

	// HasUserInfo is true when /userinfo is wired (OIDC mode + identity
	// service URL set).
	HasUserInfo bool

	// HasLoginUI is true when /oauth/authorize is fully wired with a
	// login-ui URL. When false the authorization_code grant is omitted
	// from grant_types_supported.
	HasLoginUI bool

	// RegistrationEndpoint advertises RFC 7591 DCR when set.
	RegistrationEndpoint string

	// ServiceDocumentation is an optional human-readable URL.
	ServiceDocumentation string

	// EndSessionEndpoint advertises OIDC RP-Initiated Logout 1.0 when
	// set. Typically the login-ui sign-out URL (ADR-0011). Emitted in
	// the OIDC document only.
	EndSessionEndpoint string

	// Scopes is the platform-wide list of OAuth scopes a client may
	// request — surfaced via scopes_supported. Default scopes ship in
	// [DefaultScopes] when this slice is empty.
	Scopes []string
}

// DefaultScopes is the platform-wide scope set per ADR-0010 + ADR-0012.
// OIDC scopes first, then resource scopes — clients that read the list
// in order get OIDC-aware behaviour by default.
var DefaultScopes = []string{"openid", "profile", "email", "read", "write"}

// DefaultClaims is the platform-wide claim set surfaced via
// claims_supported. Mirrors the claim shapes ADR-0010 emits in ID
// tokens; access tokens are a subset.
var DefaultClaims = []string{
	"sub", "iss", "aud", "exp", "iat", "nonce", "at_hash", "auth_time",
	"amr", "email", "email_verified", "name", "updated_at",
}

// NewMetadataBuilder returns a builder that will produce metadata
// documents reflecting the supplied configuration.
func NewMetadataBuilder(cfg MetadataBuilderConfig) *MetadataBuilder {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes
	}
	return &MetadataBuilder{
		publicBaseURL:        strings.TrimRight(cfg.PublicBaseURL, "/"),
		issuer:               cfg.Issuer,
		oidcIssuer:           cfg.OIDCIssuer,
		signingAlg:           cfg.SigningAlg,
		hasJWKS:              cfg.HasJWKS,
		hasOIDC:              cfg.OIDCIssuer != "",
		hasUserInfo:          cfg.HasUserInfo,
		hasLoginUI:           cfg.HasLoginUI,
		hasRegistration:      cfg.RegistrationEndpoint != "",
		registrationEndpoint: cfg.RegistrationEndpoint,
		serviceDocs:          cfg.ServiceDocumentation,
		endSessionEndpoint:   cfg.EndSessionEndpoint,
		scopes:               scopes,
	}
}

// OAuthMetadata returns the RFC 8414 document. OIDC-specific fields
// (userinfo, subject_types, etc.) are omitted from this document — the
// OIDC discovery endpoint surfaces them via [OIDCMetadata].
func (b *MetadataBuilder) OAuthMetadata() *domain.AuthorizationServerMetadata {
	md := b.base()
	return md
}

// OIDCMetadata returns the OIDC Discovery 1.0 document. Falls back to
// the OAuth shape when OIDC is not enabled — the caller is expected to
// skip the OIDC discovery route entirely when OIDC is off, so this path
// exists mainly for symmetry with [OAuthMetadata].
func (b *MetadataBuilder) OIDCMetadata() *domain.AuthorizationServerMetadata {
	md := b.base()
	if !b.hasOIDC {
		return md
	}
	md.Issuer = b.oidcIssuer
	if b.hasUserInfo {
		md.UserInfoEndpoint = b.publicBaseURL + "/userinfo"
	}
	if b.endSessionEndpoint != "" {
		md.EndSessionEndpoint = b.endSessionEndpoint
	}
	md.SubjectTypesSupported = []string{"public"}
	md.IDTokenSigningAlgValuesSupported = idTokenSigningAlgs(b.signingAlg)
	md.ClaimsSupported = DefaultClaims
	md.ClaimTypesSupported = []string{"normal"}
	md.ResponseModesSupported = []string{"query"}
	f := false
	md.RequestParameterSupported = &f
	md.RequestURIParameterSupported = &f
	md.RequireRequestURIRegistration = &f
	return md
}

// base composes the fields shared between the OAuth and OIDC documents.
// Conditional fields are populated based on the builder's snapshot of
// runtime config so the metadata reflects the live wiring rather than
// the operator's intent.
func (b *MetadataBuilder) base() *domain.AuthorizationServerMetadata {
	md := &domain.AuthorizationServerMetadata{
		Issuer:                b.issuer,
		AuthorizationEndpoint: b.publicBaseURL + "/oauth/authorize",
		TokenEndpoint:         b.publicBaseURL + "/oauth/token",
		IntrospectionEndpoint: b.publicBaseURL + "/oauth/introspect",
		RevocationEndpoint:    b.publicBaseURL + "/oauth/revoke",
		ResponseTypesSupported: []string{
			"code",
		},
		ScopesSupported:                           b.scopes,
		GrantTypesSupported:                       grantTypesSupported(b.hasLoginUI),
		TokenEndpointAuthMethodsSupported:         []string{"client_secret_basic", "client_secret_post", "none"},
		IntrospectionEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "bearer"},
		RevocationEndpointAuthMethodsSupported:    []string{"client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:             []string{"S256"},
		UILocalesSupported:                        []string{"en"},
	}
	if b.hasJWKS {
		md.JWKSURI = b.publicBaseURL + "/.well-known/jwks.json"
	}
	if b.hasRegistration {
		md.RegistrationEndpoint = b.registrationEndpoint
	}
	if b.serviceDocs != "" {
		md.ServiceDocumentation = b.serviceDocs
	}
	return md
}

// grantTypesSupported returns the grant types the auth-server currently
// accepts. authorization_code is included only when login-ui is wired —
// otherwise /oauth/authorize returns 501 and advertising the grant
// would surprise clients. The RFC 8693 token-exchange URN is always
// advertised because the strategy is unconditionally registered
// (ADR-0016).
func grantTypesSupported(hasLoginUI bool) []string {
	out := []string{"client_credentials", "refresh_token", string(domain.GrantTypeTokenExchange)}
	if hasLoginUI {
		out = append(out, "authorization_code")
	}
	return out
}

// idTokenSigningAlgs returns the algorithms valid for ID-token
// signatures. RS256 mode publishes the RS256 alg; HS256 mode publishes
// HS256. The ADR allows both — the active mode is determined by
// JWTConfig.SigningAlg at runtime.
func idTokenSigningAlgs(active string) []string {
	switch active {
	case "RS256":
		return []string{"RS256"}
	case "HS256":
		return []string{"HS256"}
	default:
		return []string{"RS256"}
	}
}
