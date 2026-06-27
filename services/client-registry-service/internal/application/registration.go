package application

import (
	"context"
	"fmt"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

// RegistrationService implements RFC 7591 dynamic client registration.
// It is intentionally separate from [ClientService] because the two
// surfaces target different operator trust models: ClientService is the
// admin POST /clients route; RegistrationService is the public-ish
// POST /register route with different validation, response shape, and
// error vocabulary.
type RegistrationService struct {
	repo           domain.ClientRepository
	bcryptCost     int
	emitter        audit.Emitter
	service        string
	publicBaseURL  string
	allowedScopes  []string
	allowLocalhost bool
}

// RegistrationServiceConfig captures the inputs to [NewRegistrationService]
// so the constructor stays small and self-documenting.
type RegistrationServiceConfig struct {
	// PublicBaseURL is the absolute origin clients use to reach this
	// service (e.g. "https://clients.example.com"). Used to construct
	// registration_client_uri in the response.
	PublicBaseURL string

	// AllowedScopes is the set of scopes a registered client may
	// request. Per ADR-0012 / ADR-0013, every requested scope must be
	// in this set. Empty allows any scope (used in tests).
	AllowedScopes []string

	// AllowLocalhost relaxes the redirect URI scheme check so
	// http://localhost is accepted alongside https. Set in dev.
	AllowLocalhost bool

	// BcryptCost overrides the default cost. Zero falls back to
	// bcrypt.DefaultCost.
	BcryptCost int
}

// NewRegistrationService constructs the service with config supplied at
// composition time. A nil emitter is wired in via [WithAudit] later;
// until then the service uses a no-op emitter.
func NewRegistrationService(repo domain.ClientRepository, cfg RegistrationServiceConfig) *RegistrationService {
	cost := cfg.BcryptCost
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return &RegistrationService{
		repo:           repo,
		bcryptCost:     cost,
		emitter:        audit.New(audit.NoopSink{}),
		service:        "client-registry-service",
		publicBaseURL:  strings.TrimRight(cfg.PublicBaseURL, "/"),
		allowedScopes:  cfg.AllowedScopes,
		allowLocalhost: cfg.AllowLocalhost,
	}
}

// WithAudit configures the emitter and service name (per ADR-0018 +
// ADR-0019 — agent_registered events are paid). emitter must be non-nil.
func (s *RegistrationService) WithAudit(emitter audit.Emitter, service string) *RegistrationService {
	if emitter == nil {
		panic("application: RegistrationService.WithAudit called with nil emitter")
	}
	s.emitter = emitter
	if service != "" {
		s.service = service
	}
	return s
}

// Register validates an RFC 7591 request, allocates credentials, and
// persists the client. Returns a [*domain.RegistrationError] on
// validation failure (which the HTTP layer maps to a 400-class response)
// or an error wrapping a server problem.
//
//nolint:gocyclo // RFC 7591 validation is a flat list of independent rules; splitting them obscures the spec mapping.
func (s *RegistrationService) Register(ctx context.Context, req domain.RegistrationRequest) (*domain.RegistrationResponse, error) {
	if req.SoftwareStatement != "" {
		return nil, &domain.RegistrationError{
			Code:        domain.RegistrationErrorInvalidSoftwareStatement,
			Description: "software_statement is not supported",
		}
	}

	grantTypes := defaultGrantTypes(req.GrantTypes)
	if err := validateGrantTypes(grantTypes); err != nil {
		return nil, err
	}

	responseTypes := defaultResponseTypes(req.ResponseTypes)
	if err := validateResponseTypes(responseTypes); err != nil {
		return nil, err
	}
	if err := validateGrantResponseConsistency(grantTypes, responseTypes); err != nil {
		return nil, err
	}

	authMethod := defaultAuthMethod(req.TokenEndpointAuthMethod)
	if err := validateAuthMethod(authMethod); err != nil {
		return nil, err
	}

	if err := validateRedirectURIs(req.RedirectURIs, grantTypes, s.allowLocalhost); err != nil {
		return nil, err
	}

	scopes := parseScopes(req.Scope)
	if err := s.validateScopes(scopes); err != nil {
		return nil, err
	}

	for _, candidate := range []struct {
		name, value string
	}{
		{"client_uri", req.ClientURI},
		{"logo_uri", req.LogoURI},
		{"tos_uri", req.TosURI},
		{"policy_uri", req.PolicyURI},
	} {
		if candidate.value != "" {
			if err := validateHTTPSURL(candidate.value, s.allowLocalhost); err != nil {
				return nil, invalidClientMetadata(fmt.Sprintf("%s must use https scheme", candidate.name))
			}
		}
	}
	if err := validateContacts(req.Contacts); err != nil {
		return nil, err
	}
	if err := validateClientName(req.ClientName); err != nil {
		return nil, err
	}

	clientID, err := generateHex(16)
	if err != nil {
		return nil, fmt.Errorf("generate client id: %w", err)
	}

	clientType := domain.ClientTypeConfidential
	if authMethod == domain.TokenEndpointAuthMethodNone {
		clientType = domain.ClientTypePublic
	}

	plainSecret, storedSecret, err := s.generateSecretFor(clientType)
	if err != nil {
		return nil, err
	}

	plainRegToken, regTokenHash, err := s.generateRegistrationToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	name := req.ClientName
	if name == "" {
		name = "Client " + clientID[:8]
	}

	client := &domain.OAuthClient{
		ID:                          clientID,
		Secret:                      storedSecret,
		Name:                        name,
		Type:                        clientType,
		ActorType:                   domain.ActorTypeService,
		Scopes:                      scopes,
		RedirectURIs:                req.RedirectURIs,
		GrantTypes:                  grantTypes,
		TokenEndpointAuthMethod:     authMethod,
		RegistrationAccessTokenHash: regTokenHash,
		CreatedAt:                   now,
		UpdatedAt:                   now,
		Active:                      true,
	}
	if err := s.repo.Save(ctx, client); err != nil {
		return nil, fmt.Errorf("save client: %w", err)
	}

	if err := s.emitter.Emit(ctx, audit.Event{
		EventType:      "client_registered",
		Service:        s.service,
		ActorType:      audit.ActorTypeService,
		ActorID:        client.ID,
		SubjectID:      client.ID,
		ClientID:       client.ID,
		Resource:       "endpoint:register",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "register",
		ResourceParent: s.service,
		ResourcePath:   s.service + "/endpoint/register",
		Action:         "register",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"name":                       client.Name,
			"client_type":                string(client.Type),
			"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
			"grant_types":                client.GrantTypes,
			"scopes":                     client.Scopes,
			"dynamic":                    true,
		},
	}); err != nil {
		return nil, fmt.Errorf("audit emit (client_registered): %w", err)
	}

	return &domain.RegistrationResponse{
		ClientID:                clientID,
		ClientIDIssuedAt:        now.Unix(),
		ClientSecret:            plainSecret,
		ClientSecretExpiresAt:   0,
		RegistrationAccessToken: plainRegToken,
		RegistrationClientURI:   s.publicBaseURL + "/register/" + clientID,
		ClientName:              name,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: authMethod,
		Scope:                   strings.Join(scopes, " "),
	}, nil
}

func defaultGrantTypes(in []string) []string {
	if len(in) == 0 {
		return []string{"authorization_code"}
	}
	return in
}

func defaultResponseTypes(in []string) []string {
	if len(in) == 0 {
		return []string{"code"}
	}
	return in
}

func defaultAuthMethod(in string) string {
	if in == "" {
		return domain.TokenEndpointAuthMethodNone
	}
	return in
}

func validateGrantTypes(gts []string) error {
	allowed := []string{"authorization_code", "refresh_token", "client_credentials"}
	for _, gt := range gts {
		if !slices.Contains(allowed, gt) {
			return invalidClientMetadata(fmt.Sprintf("grant_types[%q] is not supported", gt))
		}
	}
	return nil
}

func validateResponseTypes(rts []string) error {
	for _, rt := range rts {
		if rt != "code" {
			return invalidClientMetadata(fmt.Sprintf("response_types[%q] is not supported", rt))
		}
	}
	return nil
}

func validateGrantResponseConsistency(grantTypes, responseTypes []string) error {
	if slices.Contains(grantTypes, "authorization_code") && !slices.Contains(responseTypes, "code") {
		return invalidClientMetadata("authorization_code grant requires response_types to include code")
	}
	return nil
}

func validateAuthMethod(method string) error {
	allowed := []string{
		domain.TokenEndpointAuthMethodBasic,
		domain.TokenEndpointAuthMethodPost,
		domain.TokenEndpointAuthMethodNone,
	}
	if !slices.Contains(allowed, method) {
		return invalidClientMetadata(fmt.Sprintf("token_endpoint_auth_method %q is not supported", method))
	}
	return nil
}

func validateRedirectURIs(uris, grantTypes []string, allowLocalhost bool) error {
	if slices.Contains(grantTypes, "authorization_code") && len(uris) == 0 {
		return invalidRedirectURI("redirect_uris is required for authorization_code grant")
	}
	for i, raw := range uris {
		if err := validateRedirectURI(i, raw, allowLocalhost); err != nil {
			return err
		}
	}
	return nil
}

func validateRedirectURI(index int, raw string, allowLocalhost bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return invalidRedirectURI(fmt.Sprintf("redirect_uris[%d] is not a valid URI", index))
	}
	if u.Fragment != "" {
		return invalidRedirectURI(fmt.Sprintf("redirect_uris[%d] must not contain a fragment", index))
	}
	if strings.Contains(raw, "*") {
		return invalidRedirectURI(fmt.Sprintf("redirect_uris[%d] must not contain wildcards", index))
	}
	if isAllowedRedirectScheme(u, allowLocalhost) {
		return nil
	}
	return invalidRedirectURI(fmt.Sprintf("redirect_uris[%d] must use https scheme", index))
}

func isAllowedRedirectScheme(u *url.URL, allowLocalhost bool) bool {
	if u.Scheme == "https" {
		return true
	}
	return allowLocalhost && u.Scheme == "http" && isLocalhostHost(u.Hostname())
}

func invalidRedirectURI(desc string) *domain.RegistrationError {
	return &domain.RegistrationError{
		Code:        domain.RegistrationErrorInvalidRedirectURI,
		Description: desc,
	}
}

func isLocalhostHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func parseScopes(scope string) []string {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return nil
	}
	return strings.Fields(scope)
}

func (s *RegistrationService) validateScopes(scopes []string) error {
	if len(s.allowedScopes) == 0 {
		return nil
	}
	for _, scope := range scopes {
		if !slices.Contains(s.allowedScopes, scope) {
			return invalidClientMetadata(fmt.Sprintf("scope %q is not supported", scope))
		}
	}
	return nil
}

func validateHTTPSURL(raw string, allowLocalhost bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme == "https" {
		return nil
	}
	if allowLocalhost && u.Scheme == "http" && isLocalhostHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("scheme %q not allowed", u.Scheme)
}

func validateContacts(contacts []string) error {
	if len(contacts) > 10 {
		return invalidClientMetadata("contacts must contain at most 10 entries")
	}
	for i, c := range contacts {
		if _, err := mail.ParseAddress(c); err != nil {
			return invalidClientMetadata(fmt.Sprintf("contacts[%d] is not a valid email", i))
		}
	}
	return nil
}

func validateClientName(name string) error {
	if len(name) > 200 {
		return invalidClientMetadata("client_name must be at most 200 characters")
	}
	return nil
}

func invalidClientMetadata(desc string) *domain.RegistrationError {
	return &domain.RegistrationError{
		Code:        domain.RegistrationErrorInvalidClientMetadata,
		Description: desc,
	}
}

func (s *RegistrationService) generateSecretFor(t domain.ClientType) (plain, stored string, err error) {
	if t != domain.ClientTypeConfidential {
		return "", "", nil
	}
	plain, err = generateHex(32)
	if err != nil {
		return "", "", fmt.Errorf("generate client secret: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), s.bcryptCost)
	if err != nil {
		return "", "", fmt.Errorf("hash client secret: %w", err)
	}
	return plain, string(hash), nil
}

func (s *RegistrationService) generateRegistrationToken() (plain, hash string, err error) {
	plain, err = generateHex(32)
	if err != nil {
		return "", "", fmt.Errorf("generate registration access token: %w", err)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(plain), s.bcryptCost)
	if err != nil {
		return "", "", fmt.Errorf("hash registration access token: %w", err)
	}
	return plain, string(h), nil
}
