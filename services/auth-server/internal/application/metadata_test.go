package application_test

import (
	"slices"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
)

func newBuilder(t *testing.T, override func(*application.MetadataBuilderConfig)) *application.MetadataBuilder {
	t.Helper()
	cfg := application.MetadataBuilderConfig{
		PublicBaseURL: "https://auth.example.com/",
		Issuer:        "auth-server",
		SigningAlg:    "RS256",
		HasJWKS:       true,
		HasLoginUI:    true,
	}
	if override != nil {
		override(&cfg)
	}
	return application.NewMetadataBuilder(cfg)
}

func TestMetadataBuilder_OAuthMetadata_BaseFields(t *testing.T) {
	b := newBuilder(t, nil)
	md := b.OAuthMetadata()

	if md.Issuer != "auth-server" {
		t.Errorf("issuer = %q, want %q", md.Issuer, "auth-server")
	}
	if md.AuthorizationEndpoint != "https://auth.example.com/oauth/authorize" {
		t.Errorf("authorization_endpoint = %q", md.AuthorizationEndpoint)
	}
	if md.TokenEndpoint != "https://auth.example.com/oauth/token" {
		t.Errorf("token_endpoint = %q", md.TokenEndpoint)
	}
	if md.IntrospectionEndpoint != "https://auth.example.com/oauth/introspect" {
		t.Errorf("introspection_endpoint = %q", md.IntrospectionEndpoint)
	}
	if md.RevocationEndpoint != "https://auth.example.com/oauth/revoke" {
		t.Errorf("revocation_endpoint = %q", md.RevocationEndpoint)
	}
	if md.JWKSURI != "https://auth.example.com/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %q", md.JWKSURI)
	}
}

func TestMetadataBuilder_OAuthMetadata_TrimsTrailingSlash(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.PublicBaseURL = "https://auth.example.com////"
	})
	md := b.OAuthMetadata()
	if md.TokenEndpoint != "https://auth.example.com/oauth/token" {
		t.Errorf("token_endpoint = %q, want trailing slashes trimmed", md.TokenEndpoint)
	}
}

func TestMetadataBuilder_OAuthMetadata_OmitsJWKSWhenHS256(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.SigningAlg = "HS256"
		c.HasJWKS = false
	})
	md := b.OAuthMetadata()
	if md.JWKSURI != "" {
		t.Errorf("jwks_uri = %q, want empty in HS256 mode", md.JWKSURI)
	}
}

func TestMetadataBuilder_OAuthMetadata_GrantsExcludeAuthorizationCodeWithoutLoginUI(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.HasLoginUI = false
	})
	md := b.OAuthMetadata()
	if slices.Contains(md.GrantTypesSupported, "authorization_code") {
		t.Errorf("grant_types_supported = %v, must not include authorization_code without login-ui", md.GrantTypesSupported)
	}
	for _, want := range []string{"client_credentials", "refresh_token"} {
		if !slices.Contains(md.GrantTypesSupported, want) {
			t.Errorf("grant_types_supported = %v, missing %q", md.GrantTypesSupported, want)
		}
	}
}

func TestMetadataBuilder_OAuthMetadata_GrantsIncludeAuthorizationCodeWithLoginUI(t *testing.T) {
	b := newBuilder(t, nil)
	md := b.OAuthMetadata()
	if !slices.Contains(md.GrantTypesSupported, "authorization_code") {
		t.Errorf("grant_types_supported = %v, missing authorization_code", md.GrantTypesSupported)
	}
}

func TestMetadataBuilder_OAuthMetadata_OmitsRegistrationByDefault(t *testing.T) {
	b := newBuilder(t, nil)
	md := b.OAuthMetadata()
	if md.RegistrationEndpoint != "" {
		t.Errorf("registration_endpoint = %q, want empty", md.RegistrationEndpoint)
	}
}

func TestMetadataBuilder_OAuthMetadata_IncludesRegistrationWhenSet(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.RegistrationEndpoint = "https://clients.example.com/register"
	})
	md := b.OAuthMetadata()
	if md.RegistrationEndpoint != "https://clients.example.com/register" {
		t.Errorf("registration_endpoint = %q", md.RegistrationEndpoint)
	}
}

func TestMetadataBuilder_OAuthMetadata_StableInvariants(t *testing.T) {
	b := newBuilder(t, nil)
	md := b.OAuthMetadata()
	if !slices.Contains(md.ResponseTypesSupported, "code") {
		t.Errorf("response_types_supported = %v, must include code", md.ResponseTypesSupported)
	}
	if !slices.Contains(md.CodeChallengeMethodsSupported, "S256") {
		t.Errorf("code_challenge_methods_supported = %v, must include S256", md.CodeChallengeMethodsSupported)
	}
	if !slices.Contains(md.TokenEndpointAuthMethodsSupported, "client_secret_basic") {
		t.Errorf("token_endpoint_auth_methods_supported = %v", md.TokenEndpointAuthMethodsSupported)
	}
}

func TestMetadataBuilder_OAuthMetadata_AdvertisesPushedAuthorizationRequestEndpoint(t *testing.T) {
	// Arrange — RFC 9126 §5, ADR-0021. Advertised unconditionally like
	// AuthorizationEndpoint/TokenEndpoint, not gated behind a "hasPAR"
	// flag — the URL is stable even in a deployment where /oauth/par
	// itself would 501 (login-ui not wired).
	b := newBuilder(t, nil)

	// Act
	md := b.OAuthMetadata()

	// Assert
	want := "https://auth.example.com/oauth/par"
	if md.PushedAuthorizationRequestEndpoint != want {
		t.Errorf("pushed_authorization_request_endpoint = %q, want %q", md.PushedAuthorizationRequestEndpoint, want)
	}
}

// TestMetadataBuilder_OAuthMetadata_AdvertisesPrivateKeyJWT covers RFC
// 7523 §11's registered token_endpoint_auth_method value (ADR-0023).
func TestMetadataBuilder_OAuthMetadata_AdvertisesPrivateKeyJWT(t *testing.T) {
	b := newBuilder(t, nil)
	md := b.OAuthMetadata()
	if !slices.Contains(md.TokenEndpointAuthMethodsSupported, "private_key_jwt") {
		t.Errorf("token_endpoint_auth_methods_supported = %v, must include private_key_jwt", md.TokenEndpointAuthMethodsSupported)
	}
}

func TestMetadataBuilder_OAuthMetadata_OmitsOIDCFields(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.OIDCIssuer = "https://oidc.example.com"
		c.HasUserInfo = true
	})
	md := b.OAuthMetadata()
	if md.UserInfoEndpoint != "" {
		t.Errorf("userinfo_endpoint = %q, must be empty on RFC 8414 doc", md.UserInfoEndpoint)
	}
	if len(md.SubjectTypesSupported) != 0 {
		t.Errorf("subject_types_supported = %v, must be empty on RFC 8414 doc", md.SubjectTypesSupported)
	}
}

func TestMetadataBuilder_OIDCMetadata_OverridesIssuerAndIncludesOIDCFields(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.OIDCIssuer = "https://oidc.example.com"
		c.HasUserInfo = true
	})
	md := b.OIDCMetadata()
	if md.Issuer != "https://oidc.example.com" {
		t.Errorf("issuer = %q, want OIDC issuer", md.Issuer)
	}
	if md.UserInfoEndpoint != "https://auth.example.com/userinfo" {
		t.Errorf("userinfo_endpoint = %q", md.UserInfoEndpoint)
	}
	if !slices.Contains(md.SubjectTypesSupported, "public") {
		t.Errorf("subject_types_supported = %v, must include public", md.SubjectTypesSupported)
	}
	if !slices.Contains(md.IDTokenSigningAlgValuesSupported, "RS256") {
		t.Errorf("id_token_signing_alg_values_supported = %v, must include RS256", md.IDTokenSigningAlgValuesSupported)
	}
	for _, want := range []string{"sub", "iss", "aud"} {
		if !slices.Contains(md.ClaimsSupported, want) {
			t.Errorf("claims_supported = %v, missing %q", md.ClaimsSupported, want)
		}
	}
}

// TestMetadataBuilder_OIDCMetadata_AdvertisesAcrValuesSupported covers
// RFC 9470 / OIDC Discovery's acr_values_supported (ADR-0024) — this
// platform's single authentication method.
func TestMetadataBuilder_OIDCMetadata_AdvertisesAcrValuesSupported(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.OIDCIssuer = "https://oidc.example.com"
	})
	md := b.OIDCMetadata()
	if !slices.Contains(md.AcrValuesSupported, "pwd") {
		t.Errorf("acr_values_supported = %v, must include pwd", md.AcrValuesSupported)
	}
}

func TestMetadataBuilder_OAuthMetadata_OmitsAcrValuesSupported(t *testing.T) {
	b := newBuilder(t, nil)
	md := b.OAuthMetadata()
	if len(md.AcrValuesSupported) != 0 {
		t.Errorf("acr_values_supported = %v, must be empty on RFC 8414 doc", md.AcrValuesSupported)
	}
}

func TestMetadataBuilder_OIDCMetadata_OmitsUserInfoWhenDisabled(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.OIDCIssuer = "https://oidc.example.com"
		c.HasUserInfo = false
	})
	md := b.OIDCMetadata()
	if md.UserInfoEndpoint != "" {
		t.Errorf("userinfo_endpoint = %q, want empty when /userinfo disabled", md.UserInfoEndpoint)
	}
}

func TestMetadataBuilder_OIDCMetadata_FallsBackWhenOIDCDisabled(t *testing.T) {
	b := newBuilder(t, nil)
	md := b.OIDCMetadata()
	if md.Issuer != "auth-server" {
		t.Errorf("issuer = %q, want OAuth issuer when OIDC disabled", md.Issuer)
	}
	if md.UserInfoEndpoint != "" {
		t.Errorf("userinfo_endpoint = %q, want empty", md.UserInfoEndpoint)
	}
}

func TestMetadataBuilder_OAuthMetadata_AdvertisesDefaultScopes(t *testing.T) {
	b := newBuilder(t, nil)
	md := b.OAuthMetadata()
	for _, want := range application.DefaultScopes {
		if !slices.Contains(md.ScopesSupported, want) {
			t.Errorf("scopes_supported = %v, missing %q", md.ScopesSupported, want)
		}
	}
}

func TestMetadataBuilder_OAuthMetadata_AdvertisesUILocales(t *testing.T) {
	b := newBuilder(t, nil)
	md := b.OAuthMetadata()
	if !slices.Contains(md.UILocalesSupported, "en") {
		t.Errorf("ui_locales_supported = %v, must include en", md.UILocalesSupported)
	}
}

func TestMetadataBuilder_OAuthMetadata_CustomScopes(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.Scopes = []string{"openid", "tools:read"}
	})
	md := b.OAuthMetadata()
	if slices.Contains(md.ScopesSupported, "write") {
		t.Errorf("custom scope override must replace defaults; got %v", md.ScopesSupported)
	}
	if !slices.Contains(md.ScopesSupported, "tools:read") {
		t.Errorf("scopes_supported = %v, missing custom scope", md.ScopesSupported)
	}
}

func TestMetadataBuilder_OIDCMetadata_EmitsRequestParamFlags(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.OIDCIssuer = "https://oidc.example.com"
	})
	md := b.OIDCMetadata()
	if md.RequestParameterSupported == nil || *md.RequestParameterSupported {
		t.Errorf("request_parameter_supported = %v, want explicit false", md.RequestParameterSupported)
	}
	if md.RequestURIParameterSupported == nil || *md.RequestURIParameterSupported {
		t.Errorf("request_uri_parameter_supported = %v, want explicit false", md.RequestURIParameterSupported)
	}
	if md.RequireRequestURIRegistration == nil || *md.RequireRequestURIRegistration {
		t.Errorf("require_request_uri_registration = %v, want explicit false", md.RequireRequestURIRegistration)
	}
}

func TestMetadataBuilder_OIDCMetadata_EmitsClaimTypes(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.OIDCIssuer = "https://oidc.example.com"
	})
	md := b.OIDCMetadata()
	if !slices.Contains(md.ClaimTypesSupported, "normal") {
		t.Errorf("claim_types_supported = %v, must include normal", md.ClaimTypesSupported)
	}
}

func TestMetadataBuilder_OIDCMetadata_EndSessionEndpoint(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.OIDCIssuer = "https://oidc.example.com"
		c.EndSessionEndpoint = "https://login.example.com/sign-out"
	})
	md := b.OIDCMetadata()
	if md.EndSessionEndpoint != "https://login.example.com/sign-out" {
		t.Errorf("end_session_endpoint = %q", md.EndSessionEndpoint)
	}
}

func TestMetadataBuilder_OAuthMetadata_IncludesServiceDocs(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.ServiceDocumentation = "https://docs.example.com/auth"
	})
	md := b.OAuthMetadata()
	if md.ServiceDocumentation != "https://docs.example.com/auth" {
		t.Errorf("service_documentation = %q", md.ServiceDocumentation)
	}
}

func TestMetadataBuilder_OIDCMetadata_DefaultsToRS256WhenAlgUnset(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.OIDCIssuer = "https://oidc.example.com"
		c.SigningAlg = ""
	})
	md := b.OIDCMetadata()
	if !slices.Contains(md.IDTokenSigningAlgValuesSupported, "RS256") {
		t.Errorf("id_token_signing_alg_values_supported = %v, must default to RS256", md.IDTokenSigningAlgValuesSupported)
	}
}

func TestMetadataBuilder_OAuthMetadata_OmitsRequestParamFlags(t *testing.T) {
	// RFC 8414 doc — OIDC-only flags must not appear.
	b := newBuilder(t, nil)
	md := b.OAuthMetadata()
	if md.RequestParameterSupported != nil {
		t.Errorf("request_parameter_supported emitted on RFC 8414 doc")
	}
}

func TestMetadataBuilder_OAuthMetadata_AdvertisesAuthorizationDetailsTypes(t *testing.T) {
	b := newBuilder(t, nil)
	md := b.OAuthMetadata()
	if !slices.Contains(md.AuthorizationDetailsTypesSupported, "mcp_tool") {
		t.Errorf("authorization_details_types_supported = %v, must include mcp_tool", md.AuthorizationDetailsTypesSupported)
	}
	if !slices.Contains(md.AuthorizationDetailsTypesSupported, "resource") {
		t.Errorf("authorization_details_types_supported = %v, must include resource", md.AuthorizationDetailsTypesSupported)
	}
}

// TestMetadataBuilder_OAuthMetadata_AdvertisesDPoPSigningAlgs and its OIDC
// counterpart cover RFC 9449 (ADR-0025): dpop_signing_alg_values_supported
// is an OAuth-layer capability, so — unlike OIDC-only fields — it must
// appear on both documents unconditionally.
func TestMetadataBuilder_OAuthMetadata_AdvertisesDPoPSigningAlgs(t *testing.T) {
	b := newBuilder(t, nil)
	md := b.OAuthMetadata()
	if !slices.Contains(md.DPoPSigningAlgValuesSupported, "ES256") {
		t.Errorf("dpop_signing_alg_values_supported = %v, must include ES256", md.DPoPSigningAlgValuesSupported)
	}
	if !slices.Contains(md.DPoPSigningAlgValuesSupported, "RS256") {
		t.Errorf("dpop_signing_alg_values_supported = %v, must include RS256", md.DPoPSigningAlgValuesSupported)
	}
}

func TestMetadataBuilder_OIDCMetadata_AdvertisesDPoPSigningAlgs(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.OIDCIssuer = "https://oidc.example.com"
	})
	md := b.OIDCMetadata()
	if !slices.Contains(md.DPoPSigningAlgValuesSupported, "ES256") {
		t.Errorf("dpop_signing_alg_values_supported = %v, must include ES256", md.DPoPSigningAlgValuesSupported)
	}
}

func TestMetadataBuilder_OIDCMetadata_HS256ReportsHS256Alg(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.OIDCIssuer = "https://oidc.example.com"
		c.SigningAlg = "HS256"
		c.HasJWKS = false
	})
	md := b.OIDCMetadata()
	if !slices.Contains(md.IDTokenSigningAlgValuesSupported, "HS256") {
		t.Errorf("id_token_signing_alg_values_supported = %v, must include HS256", md.IDTokenSigningAlgValuesSupported)
	}
}

func TestMetadataBuilder_OAuthMetadata_AdvertisesDeviceAuthorizationEndpoint(t *testing.T) {
	// ADR-0022: advertised unconditionally, like AuthorizationEndpoint and
	// TokenEndpoint, regardless of whether login-ui is wired.
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.HasLoginUI = false
	})
	md := b.OAuthMetadata()
	if md.DeviceAuthorizationEndpoint != "https://auth.example.com/device_authorization" {
		t.Errorf("device_authorization_endpoint = %q", md.DeviceAuthorizationEndpoint)
	}
}

func TestMetadataBuilder_OAuthMetadata_GrantsIncludeDeviceCodeWithLoginUI(t *testing.T) {
	b := newBuilder(t, nil)
	md := b.OAuthMetadata()
	if !slices.Contains(md.GrantTypesSupported, "urn:ietf:params:oauth:grant-type:device_code") {
		t.Errorf("grant_types_supported = %v, missing device_code grant", md.GrantTypesSupported)
	}
}

func TestMetadataBuilder_OAuthMetadata_GrantsExcludeDeviceCodeWithoutLoginUI(t *testing.T) {
	b := newBuilder(t, func(c *application.MetadataBuilderConfig) {
		c.HasLoginUI = false
	})
	md := b.OAuthMetadata()
	if slices.Contains(md.GrantTypesSupported, "urn:ietf:params:oauth:grant-type:device_code") {
		t.Errorf("grant_types_supported = %v, must not include device_code without login-ui", md.GrantTypesSupported)
	}
}
