package http

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/jedi-knights/go-logging/pkg/logging"

	"github.com/jedi-knights/go-platform/httputil"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// AuthorizeConfig bundles the dependencies the /oauth/authorize and
// /internal/issue-code endpoints need. Passing nil to NewHandler preserves
// the original stub (501 Not Implemented for /oauth/authorize, 404 for
// /internal/issue-code) so tests that exercise other endpoints do not have
// to wire the authorize subsystem.
//
// IDGenerator is optional; when nil it defaults to 32 bytes of CSPRNG entropy
// hex-encoded (64 chars). Tests can inject a deterministic generator.
//
// AuthCodeIssuer and IssueCodeBearer are required to serve /internal/issue-code.
// IssueCodeBearer is the shared service token presented by login-ui; comparison
// is constant-time. When IssueCodeBearer is empty, /internal/issue-code returns
// 404 even if AuthCodeIssuer is wired — a missing token means the operator has
// not opted into the endpoint.
type AuthorizeConfig struct {
	ClientLookup    ports.ClientLookup
	ChallengeRepo   domain.LoginChallengeRepository
	LoginUIURL      string
	ChallengeTTL    time.Duration
	IDGenerator     func() (string, error)
	AuthCodeIssuer  ports.AuthorizationCodeIssuer
	IssueCodeBearer string
}

// Handler holds all HTTP handler dependencies.
type Handler struct {
	issuer       ports.TokenIssuer
	introspector ports.TokenIntrospector
	revoker      ports.TokenRevoker
	clientAuth   ports.ClientAuthenticator
	logger       logging.Logger
	// introspectionSecret is a pre-shared secret for the /oauth/introspect endpoint.
	// When non-empty, callers must supply Authorization: Bearer <secret>.
	// When empty, callers must authenticate with client credentials.
	introspectionSecret string
	rateLimiter         *fixedWindowLimiter
	authorize           *AuthorizeConfig

	// auditEmitter is consulted on introspection and revocation per ADR-0018.
	// Defaults to a no-op so tests and callers that pre-date the audit feature
	// keep working. Wire a real emitter via [Handler.WithAudit] at the
	// composition root.
	auditEmitter audit.Emitter
	auditService string
}

func NewHandler(
	issuer ports.TokenIssuer,
	introspector ports.TokenIntrospector,
	revoker ports.TokenRevoker,
	clientAuth ports.ClientAuthenticator,
	logger logging.Logger,
	introspectionSecret string,
	authorize *AuthorizeConfig,
) *Handler {
	return &Handler{
		issuer:              issuer,
		introspector:        introspector,
		revoker:             revoker,
		clientAuth:          clientAuth,
		logger:              logger,
		introspectionSecret: introspectionSecret,
		rateLimiter:         newFixedWindowLimiter(20, time.Minute),
		authorize:           authorize,
		auditEmitter:        audit.New(audit.NoopSink{}),
		auditService:        "auth-server",
	}
}

// WithAudit configures the handler's audit emitter and service name.
// Returns the receiver to allow chained construction at the composition
// root. emitter must be non-nil. service is used as Event.Service on every
// emitted token_introspected and token_revoked event.
//
// Per ADR-0019, introspect and revoke are billable / accounting-relevant
// operations: an emit failure is surfaced to the caller and degrades to
// the same safe behaviour each handler already implements when its
// downstream call fails (introspect → {"active": false} per RFC 7662 §2.2;
// revoke → 500). Both behaviours preserve token-confidentiality semantics.
func (h *Handler) WithAudit(emitter audit.Emitter, service string) *Handler {
	if emitter == nil {
		panic("http: WithAudit called with nil emitter")
	}
	h.auditEmitter = emitter
	if service != "" {
		h.auditService = service
	}
	return h
}

// introspectionSecretActor is the sentinel actor identifier used when the
// introspection endpoint authenticates with the pre-shared secret rather
// than client credentials. Stable so downstream consumers can recognise
// the introspection-service principal in audit aggregates.
const introspectionSecretActor = "introspection-service"

// oauthErrorCode is an RFC 6749 §5.2 error code sent in the "error" field.
// A named type prevents silent transposition with the description parameter.
type oauthErrorCode string

// unsupportedTokenType is the RFC 7009 §2.2 error code for token types the server
// cannot revoke. Declared here so writeOAuthError callers use the typed constant
// rather than a bare string, preventing silent transposition.
const unsupportedTokenType oauthErrorCode = "unsupported_token_type"

// writeOAuthError writes an RFC 6749-compliant JSON error response.
// Sets both Cache-Control: no-store and Pragma: no-cache per RFC 6749 §5.1.
func writeOAuthError(w http.ResponseWriter, logger logging.Logger, code oauthErrorCode, description string, httpStatus int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(httpStatus)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"error":             string(code),
		"error_description": description,
	}); err != nil {
		logger.Error("failed to encode oauth error", "error", err)
	}
}

// Token handles POST /oauth/token.
//
// @Summary      Issue access token
// @Description  Issues an OAuth2 access token using the specified grant type (RFC 6749)
// @Tags         oauth
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        grant_type    formData  string  true  "OAuth2 grant type"
// @Param        client_id     formData  string  true  "Client identifier"
// @Param        client_secret formData  string  true  "Client secret"
// @Param        scope         formData  string  false "Space-delimited list of scopes"
// @Param        code          formData  string  false "Authorization code"
// @Param        code_verifier formData  string  false "PKCE code verifier"
// @Param        redirect_uri  formData  string  false "Redirect URI"
// @Success      200  {object}  domain.GrantResponse
// @Failure      400  {object}  httputil.ErrorResponse
// @Router       /oauth/token [post]
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	// Per RFC 6819 §4.3.2: rate-limit by client IP to slow brute-force attacks.
	if !h.rateLimiter.Allow(clientIP(r)) {
		// RFC 6585 §4: include Retry-After on 429 responses.
		w.Header().Set("Retry-After", "60")
		writeOAuthError(w, h.logger, "server_error", "too many requests", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, h.logger, "invalid_request", "invalid form data", http.StatusBadRequest)
		return
	}

	req, ok := parseGrantRequest(w, r, h.logger)
	if !ok {
		return
	}

	resp, err := h.issuer.IssueToken(r.Context(), req)
	if err != nil {
		h.logger.Error("token issuance failed", "error", err.Error())
		writeTokenError(w, h.logger, err)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	httputil.WriteJSON(w, http.StatusOK, resp)
}

// parseGrantRequest extracts and validates the OAuth2 token request fields.
// Checks Authorization: Basic first per RFC 6749 §2.3.1, then falls back to
// form body parameters. Writes an RFC 6749 §5.2 invalid_request error and
// returns false if any required field is missing.
func parseGrantRequest(w http.ResponseWriter, r *http.Request, logger logging.Logger) (domain.GrantRequest, bool) {
	grantType := domain.GrantType(r.FormValue("grant_type"))
	if grantType == "" {
		writeOAuthError(w, logger, "invalid_request", "grant_type is required", http.StatusBadRequest)
		return domain.GrantRequest{}, false
	}

	// RFC 6749 §2.3.1: clients SHOULD use HTTP Basic Auth; form body is a fallback.
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	if clientID == "" {
		writeOAuthError(w, logger, "invalid_request", "client_id is required", http.StatusBadRequest)
		return domain.GrantRequest{}, false
	}
	if clientSecret == "" {
		writeOAuthError(w, logger, "invalid_request", "client_secret is required", http.StatusBadRequest)
		return domain.GrantRequest{}, false
	}

	var scopes []string
	if scopeStr := r.FormValue("scope"); scopeStr != "" {
		scopes = strings.Fields(scopeStr)
	}

	return domain.GrantRequest{
		GrantType:    grantType,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Code:         r.FormValue("code"),
		CodeVerifier: r.FormValue("code_verifier"),
		RedirectURI:  r.FormValue("redirect_uri"),
	}, true
}

// writeTokenError maps an application error to an RFC 6749-compliant OAuth2 error response.
// Order matters: more-specific sentinels (ADR-0009) are checked before the
// apperrors fallbacks so a sentinel-wrapped Unauthorized is not silently
// remapped by the IsUnauthorized branch.
func writeTokenError(w http.ResponseWriter, logger logging.Logger, err error) {
	if errors.Is(err, application.ErrUnsupportedGrantType) {
		writeOAuthError(w, logger, "unsupported_grant_type", "grant type not supported", http.StatusBadRequest)
		return
	}
	if errors.Is(err, application.ErrInvalidRequest) {
		writeOAuthError(w, logger, "invalid_request", err.Error(), http.StatusBadRequest)
		return
	}
	if errors.Is(err, application.ErrInvalidGrant) {
		writeOAuthError(w, logger, "invalid_grant", err.Error(), http.StatusBadRequest)
		return
	}
	if errors.Is(err, application.ErrUnauthorizedClient) {
		writeOAuthError(w, logger, "unauthorized_client", err.Error(), http.StatusBadRequest)
		return
	}
	if apperrors.IsUnauthorized(err) {
		// RFC 6749 §5.2 requires WWW-Authenticate on 401 responses.
		w.Header().Set("WWW-Authenticate", `Basic realm="auth-server"`)
		writeOAuthError(w, logger, "invalid_client", "client authentication failed", http.StatusUnauthorized)
		return
	}
	if apperrors.IsForbidden(err) {
		// RFC 6749 §5.2: invalid_scope must use HTTP 400, not 403.
		writeOAuthError(w, logger, "invalid_scope", "requested scope not permitted", http.StatusBadRequest)
		return
	}
	writeOAuthError(w, logger, "server_error", "internal server error", http.StatusInternalServerError)
}

// Authorize handles GET /oauth/authorize per ADR-0011.
//
// The handler validates the request parameters, looks up the client,
// validates the redirect_uri exact-match and scope subset, persists a
// short-lived LoginChallenge, and 302-redirects the user-agent to login-ui
// with only the opaque challenge ID. The full set of authorize parameters
// stays server-side.
//
// Error-routing follows RFC 6749 §3.1.2.4 and §4.1.2.1:
//   - bad client_id or redirect_uri → render the error, do NOT redirect to
//     the (untrusted) request URI.
//   - other parameter errors after client/redirect_uri have been validated
//     → 302 back to the client with ?error=&state=.
//
// @Summary      Authorization endpoint
// @Description  Starts an OAuth 2.1 + OIDC authorize flow (ADR-0011)
// @Tags         oauth
// @Produce      html
// @Success      302  "Redirect to login-ui sign-in page"
// @Router       /oauth/authorize [get]
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	if h.authorize == nil {
		http.Error(w, "not yet implemented", http.StatusNotImplemented)
		return
	}
	req := parseAuthorizeRequest(r)
	if req.ClientID == "" {
		writeOAuthError(w, h.logger, "invalid_request", "client_id is required", http.StatusBadRequest)
		return
	}
	client, err := h.authorize.ClientLookup.Lookup(r.Context(), req.ClientID)
	if err != nil {
		writeOAuthError(w, h.logger, "invalid_request", "unknown client", http.StatusBadRequest)
		return
	}
	if !redirectURIMatches(client.RedirectURIs, req.RedirectURI) {
		writeOAuthError(w, h.logger, "invalid_request", "redirect_uri not registered for client", http.StatusBadRequest)
		return
	}
	if code, desc := validateAuthorizeParams(req, client); code != "" {
		redirectAuthorizeError(w, r, req.RedirectURI, req.State, code, desc)
		return
	}
	h.persistChallengeAndRedirect(w, r, req)
}

// IssueCode handles POST /internal/issue-code per ADR-0011.
//
// login-ui calls this endpoint after the user has authenticated and approved
// the consent screen. auth-server atomically Consumes the LoginChallenge,
// validates that the granted-scope set is a subset of the request scopes,
// mints an authorization code, and returns it alongside the redirect_uri
// and state copied straight from the challenge. login-ui then 302s the
// user-agent to <redirect_uri>?code=<code>&state=<state>.
//
// Authentication is a shared service bearer token (constant-time compare);
// this is NOT a user-facing endpoint and is not advertised in RFC 8414
// metadata. When AuthorizeConfig is nil or IssueCodeBearer is empty the
// route returns 404 — operators that have not opted into login-ui get no
// hint that the endpoint exists.
func (h *Handler) IssueCode(w http.ResponseWriter, r *http.Request) {
	if !h.issueCodeEnabled() {
		http.NotFound(w, r)
		return
	}
	if !h.verifyServiceBearer(r) {
		writeOAuthError(w, h.logger, "invalid_client", "service authentication failed", http.StatusUnauthorized)
		return
	}
	body, ok := decodeIssueCodeBody(w, r, h.logger)
	if !ok {
		return
	}
	challenge, err := h.authorize.ChallengeRepo.Consume(r.Context(), body.LoginChallenge)
	if err != nil {
		writeOAuthError(w, h.logger, "invalid_request", "unknown or expired login_challenge", http.StatusBadRequest)
		return
	}
	if !scopesAreSubset(body.ConsentGranted, challenge.Scopes) {
		writeOAuthError(w, h.logger, "invalid_request", "consent_granted exceeds requested scope", http.StatusBadRequest)
		return
	}
	h.mintAndRespond(w, r, challenge, body)
}

// issueCodeEnabled reports whether /internal/issue-code is wired. Three
// independent conditions guard the endpoint; collapsing them here keeps
// IssueCode's cyclomatic complexity within the project's cap of 7.
func (h *Handler) issueCodeEnabled() bool {
	return h.authorize != nil && h.authorize.IssueCodeBearer != "" && h.authorize.AuthCodeIssuer != nil
}

// decodeIssueCodeBody reads the JSON body, enforces the request size cap,
// and verifies the required fields. Writes the error response and returns
// false on any failure.
func decodeIssueCodeBody(w http.ResponseWriter, r *http.Request, logger logging.Logger) (issueCodeRequest, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var body issueCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeOAuthError(w, logger, "invalid_request", "malformed json", http.StatusBadRequest)
		return body, false
	}
	if body.LoginChallenge == "" || body.SessionID == "" {
		writeOAuthError(w, logger, "invalid_request", "login_challenge and session_id are required", http.StatusBadRequest)
		return body, false
	}
	return body, true
}

// issueCodeRequest is the JSON body shape of /internal/issue-code per ADR-0011.
// session_id is currently treated as the subject ID until SessionStore lands
// in a follow-up commit.
type issueCodeRequest struct {
	LoginChallenge string   `json:"login_challenge"`
	SessionID      string   `json:"session_id"`
	ConsentGranted []string `json:"consent_granted"`
}

type issueCodeResponse struct {
	Code        string `json:"code"`
	RedirectURI string `json:"redirect_uri"`
	State       string `json:"state"`
}

func (h *Handler) verifyServiceBearer(r *http.Request) bool {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	presented := auth[len(prefix):]
	expected := h.authorize.IssueCodeBearer
	if len(presented) != len(expected) {
		// Constant-time compare requires equal-length inputs; bail before
		// invoking subtle to avoid the length-leak side channel.
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
}

// mintAndRespond runs the AuthorizationCodeIssuer.Issue call and writes the
// response. Extracted from IssueCode to keep the cyclomatic complexity within
// bounds.
func (h *Handler) mintAndRespond(w http.ResponseWriter, r *http.Request, challenge *domain.LoginChallenge, body issueCodeRequest) {
	scopes := body.ConsentGranted
	if len(scopes) == 0 {
		scopes = challenge.Scopes
	}
	req := ports.IssueCodeRequest{
		ClientID:            challenge.ClientID,
		Subject:             body.SessionID,
		RedirectURI:         challenge.RedirectURI,
		Scopes:              scopes,
		CodeChallenge:       challenge.CodeChallenge,
		CodeChallengeMethod: challenge.CodeChallengeMethod,
		Nonce:               challenge.Nonce,
	}
	code, err := h.authorize.AuthCodeIssuer.Issue(r.Context(), req)
	if err != nil {
		h.logger.Error("issue-code: issuer failed", "error", err)
		writeOAuthError(w, h.logger, "server_error", "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httputil.WriteJSON(w, http.StatusOK, issueCodeResponse{
		Code:        code,
		RedirectURI: challenge.RedirectURI,
		State:       challenge.State,
	})
}

// authorizeRequest holds the parsed query-string of /oauth/authorize. Fields
// mirror RFC 6749 §4.1.1 and OIDC Core §3.1.2.1. Empty strings indicate the
// parameter was not present.
type authorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
	MaxAge              string
}

func parseAuthorizeRequest(r *http.Request) authorizeRequest {
	q := r.URL.Query()
	return authorizeRequest{
		ResponseType:        q.Get("response_type"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Prompt:              q.Get("prompt"),
		MaxAge:              q.Get("max_age"),
	}
}

// redirectURIMatches enforces the exact-match policy from ADR-0009 — no
// substring, prefix, or query-difference tolerance.
func redirectURIMatches(registered []string, presented string) bool {
	if presented == "" {
		return false
	}
	return slices.Contains(registered, presented)
}

// validateAuthorizeParams returns ("", "") on success, or an RFC 6749 §5.2
// error code + description for the failure. The handler reports the error
// by redirecting to the (already validated) redirect_uri.
func validateAuthorizeParams(req authorizeRequest, client *domain.Client) (code, description string) {
	if req.ResponseType != "code" {
		return "unsupported_response_type", "only response_type=code is supported"
	}
	if req.CodeChallenge == "" {
		return "invalid_request", "code_challenge is required (PKCE-S256 mandatory)"
	}
	if req.CodeChallengeMethod != "S256" {
		return "invalid_request", "code_challenge_method must be S256"
	}
	requested := parseScopes(req.Scope)
	if !scopesAreSubset(requested, client.Scopes) {
		return "invalid_scope", "requested scope is not registered for client"
	}
	return "", ""
}

// parseScopes splits a space-delimited scope string per RFC 6749 §3.3.
// Returns nil for an empty input (matches "scope omitted" semantics).
func parseScopes(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// scopesAreSubset reports whether every requested scope is in the allowed
// list. O(n+m) — builds a set once. An empty request is valid: callers can
// omit scope entirely (the issued token then carries the client's default).
func scopesAreSubset(requested, allowed []string) bool {
	if len(requested) == 0 {
		return true
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		allowedSet[s] = struct{}{}
	}
	for _, s := range requested {
		if _, ok := allowedSet[s]; !ok {
			return false
		}
	}
	return true
}

// persistChallengeAndRedirect mints a fresh opaque ID, saves a LoginChallenge
// holding every authorize parameter, and 302s to login-ui. Extracted from
// Authorize to keep the cyclomatic complexity within bounds.
func (h *Handler) persistChallengeAndRedirect(w http.ResponseWriter, r *http.Request, req authorizeRequest) {
	id, err := h.generateChallengeID()
	if err != nil {
		h.logger.Error("authorize: generate challenge id", "error", err)
		writeOAuthError(w, h.logger, "server_error", "internal server error", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	maxAge, _ := strconvAtoiSafe(req.MaxAge)
	challenge := &domain.LoginChallenge{
		ID:                  id,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scopes:              parseScopes(req.Scope),
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Prompt:              parseScopes(req.Prompt),
		MaxAge:              maxAge,
		CreatedAt:           now,
		ExpiresAt:           now.Add(h.authorize.ChallengeTTL),
	}
	if err := h.authorize.ChallengeRepo.Save(r.Context(), challenge); err != nil {
		h.logger.Error("authorize: save login challenge", "error", err)
		writeOAuthError(w, h.logger, "server_error", "internal server error", http.StatusInternalServerError)
		return
	}
	target := h.authorize.LoginUIURL + "/sign-in?login_challenge=" + url.QueryEscape(id)
	http.Redirect(w, r, target, http.StatusFound)
}

// generateChallengeID returns 32 bytes of CSPRNG entropy hex-encoded, or the
// IDGenerator override when the AuthorizeConfig supplies one. 64 hex chars
// give 256 bits of entropy — collision-resistant well past the 5-minute TTL.
func (h *Handler) generateChallengeID() (string, error) {
	if h.authorize.IDGenerator != nil {
		return h.authorize.IDGenerator()
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// redirectAuthorizeError sends a 302 back to the client redirect_uri with
// ?error=&error_description=&state= per RFC 6749 §4.1.2.1. The redirect URI
// has already been validated against the client's registered list, so this
// path is safe to take.
func redirectAuthorizeError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		// Defense in depth: a redirect_uri that matched the registered set but
		// fails to parse is a registry bug. Falling back to a 400 with the
		// error code keeps the user-agent off any unknown URI.
		http.Error(w, code, http.StatusBadRequest)
		return
	}
	q := target.Query()
	q.Set("error", code)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// strconvAtoiSafe parses a non-negative integer; returns 0 on any failure.
// max_age is the only field where 0 is a meaningful "not requested" default,
// so swallowing the parse error matches the rest of the field shape.
func strconvAtoiSafe(s string) (int, bool) {
	if s == "" {
		return 0, true
	}
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		n = n*10 + int(ch-'0')
	}
	return n, true
}

// Introspect handles POST /oauth/introspect.
//
// RFC 7662 §2.1: callers must authenticate. This endpoint accepts either a
// pre-shared bearer secret (Authorization: Bearer <secret>) or client credentials
// (Authorization: Basic or form body), whichever is configured.
//
// @Summary      Introspect token
// @Description  Validates and returns metadata for a token per RFC 7662
// @Tags         oauth
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        token  formData  string  true  "Token to introspect"
// @Success      200  {object}  domain.IntrospectResponse
// @Failure      400  {object}  httputil.ErrorResponse
// @Router       /oauth/introspect [post]
func (h *Handler) Introspect(w http.ResponseWriter, r *http.Request) {
	// Per RFC 6819 §4.3.2: apply the same per-IP rate limit as the token endpoint.
	if !h.rateLimiter.Allow(clientIP(r)) {
		w.Header().Set("Retry-After", "60")
		writeOAuthError(w, h.logger, "server_error", "too many requests", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		// RFC 7662 §2.2: always return 200 with {"active": false} rather than a 4xx.
		// A 4xx from introspection can be misread by resource servers as a transient
		// error, causing them to allow the request through.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		httputil.WriteJSON(w, http.StatusOK, domain.IntrospectResponse{Active: false})
		return
	}

	actor, ok := h.authenticateIntrospectionCaller(w, r)
	if !ok {
		return
	}

	// RFC 7662 §2.1: token_type_hint is an optional hint. Accept the field but do
	// not use it to optimize the lookup — optimization is not yet implemented.
	_ = r.FormValue("token_type_hint")

	token := r.FormValue("token")
	if token == "" {
		// RFC 7662 §2.2: a missing token cannot be active — return inactive rather than 400.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		httputil.WriteJSON(w, http.StatusOK, domain.IntrospectResponse{Active: false})
		return
	}

	resp, err := h.introspector.Introspect(r.Context(), token)
	if err != nil {
		// RFC 7662 §2.2: infrastructure errors must not produce a non-200 response.
		// Resource servers may interpret non-200 as "allow through"; returning
		// {"active": false} is the safe, spec-compliant failure mode.
		logging.WithTraceFromContext(r.Context(), h.logger).Error("introspection failed", "error", err.Error())
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		httputil.WriteJSON(w, http.StatusOK, domain.IntrospectResponse{Active: false})
		return
	}

	// ADR-0018: every introspection emits a token_introspected event with
	// the caller as actor, the introspected token's subject as subject_id,
	// and the active/inactive outcome in attrs. ADR-0019: an emit failure
	// surfaces as the same RFC 7662-safe inactive response — non-2xx from
	// introspection is unsafe per §2.2.
	if err := h.emitTokenIntrospected(r.Context(), actor, resp); err != nil {
		logging.WithTraceFromContext(r.Context(), h.logger).Error("audit emit (token_introspected) failed", "error", err.Error())
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		httputil.WriteJSON(w, http.StatusOK, domain.IntrospectResponse{Active: false})
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	httputil.WriteJSON(w, http.StatusOK, resp)
}

// emitTokenIntrospected emits a token_introspected audit event per
// ADR-0018. The active/inactive outcome is carried in attrs because it is
// the result of the operation, not the authorization decision — the caller
// authenticated, so decision is always allow.
func (h *Handler) emitTokenIntrospected(ctx context.Context, actor string, resp *domain.IntrospectResponse) error {
	actorType := audit.ActorTypeService
	if actor == introspectionSecretActor {
		actorType = audit.ActorTypeService
	}
	return h.auditEmitter.Emit(ctx, audit.Event{
		EventType:      "token_introspected",
		Service:        h.auditService,
		ActorType:      actorType,
		ActorID:        actor,
		SubjectID:      resp.Subject,
		ClientID:       actor,
		Resource:       "token:access",
		ResourceKind:   audit.ResourceKindToken,
		ResourceID:     "access",
		ResourceParent: h.auditService,
		ResourcePath:   h.auditService + "/token/access",
		Action:         "introspect",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"active":              resp.Active,
			"introspected_jti":    resp.JTI,
			"introspected_client": resp.ClientID,
		},
	})
}

// authenticateIntrospectionCaller enforces RFC 7662 §2.1 caller authentication.
// When introspectionSecret is set: require Authorization: Bearer <secret>.
// Otherwise: require client credentials (Basic Auth or form body).
// Returns the authenticated actor identifier and true on success; an empty
// actor and false on failure (with a 401 already written to w).
func (h *Handler) authenticateIntrospectionCaller(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.introspectionSecret != "" {
		if authenticateWithSecret(w, r, h.introspectionSecret, h.logger) {
			return introspectionSecretActor, true
		}
		return "", false
	}
	return h.authenticateClientCredentials(w, r)
}

// authenticateWithSecret validates Authorization: Bearer <secret>.
// Returns false and writes a 401 WWW-Authenticate challenge if the header is absent or wrong.
func authenticateWithSecret(w http.ResponseWriter, r *http.Request, secret string, logger logging.Logger) bool {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if !strings.HasPrefix(auth, "Bearer ") || subtle.ConstantTimeCompare([]byte(token), []byte(secret)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="auth-server"`)
		writeOAuthError(w, logger, "invalid_client", "invalid introspection secret", http.StatusUnauthorized)
		return false
	}
	return true
}

// authenticateClientCredentials validates client credentials from Basic Auth or form body.
// Returns the authenticated client_id and true on success; empty actor and false
// on failure (with a 401 already written to w).
func (h *Handler) authenticateClientCredentials(w http.ResponseWriter, r *http.Request) (string, bool) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}
	if clientID == "" || clientSecret == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="auth-server"`)
		writeOAuthError(w, h.logger, "invalid_client", "client authentication required", http.StatusUnauthorized)
		return "", false
	}
	if _, err := h.clientAuth.Authenticate(r.Context(), clientID, clientSecret); err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="auth-server"`)
		writeOAuthError(w, h.logger, "invalid_client", "client authentication failed", http.StatusUnauthorized)
		return "", false
	}
	return clientID, true
}

// Revoke handles POST /oauth/revoke.
//
// RFC 7009 §2: callers must authenticate with client credentials.
//
// @Summary      Revoke token
// @Description  Revokes a token per RFC 7009
// @Tags         oauth
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        token  formData  string  true  "Token to revoke"
// @Success      200  "Token revoked"
// @Failure      400  {object}  httputil.ErrorResponse
// @Router       /oauth/revoke [post]
func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	// Per RFC 6819 §4.3.2: rate-limit revocation endpoint same as token endpoint.
	if !h.rateLimiter.Allow(clientIP(r)) {
		w.Header().Set("Retry-After", "60")
		writeOAuthError(w, h.logger, "server_error", "too many requests", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, h.logger, "invalid_request", "invalid form data", http.StatusBadRequest)
		return
	}

	// RFC 7009 §2: the revocation endpoint requires client authentication.
	actor, ok := h.authenticateClientCredentials(w, r)
	if !ok {
		return
	}

	if !h.validateTokenTypeHint(w, r) {
		return
	}

	token := r.FormValue("token")
	if token == "" {
		writeOAuthError(w, h.logger, "invalid_request", "token is required", http.StatusBadRequest)
		return
	}

	if !h.doRevoke(w, r, token) {
		return
	}

	// ADR-0018: emit token_revoked after successful revocation. Per
	// ADR-0019's paid-event policy a durable-sink failure fails the
	// request — the same shape as token issuance.
	if err := h.emitTokenRevoked(r.Context(), actor, r.FormValue("token_type_hint")); err != nil {
		h.logger.Error("audit emit (token_revoked) failed", "error", err.Error())
		writeOAuthError(w, h.logger, "server_error", "revocation succeeded but audit emit failed", http.StatusInternalServerError)
		return
	}

	// Success path: all error paths above return early.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
}

// emitTokenRevoked emits a token_revoked audit event per ADR-0018. The
// token's subject is not parsed from the presented token — the token may
// already be invalid, and the revocation endpoint deliberately does not
// validate token contents (RFC 7009 §2.2). The actor is the authenticated
// client; that and the type hint are enough for an audit trail.
func (h *Handler) emitTokenRevoked(ctx context.Context, actor, typeHint string) error {
	return h.auditEmitter.Emit(ctx, audit.Event{
		EventType:      "token_revoked",
		Service:        h.auditService,
		ActorType:      audit.ActorTypeService,
		ActorID:        actor,
		ClientID:       actor,
		Resource:       "token:access",
		ResourceKind:   audit.ResourceKindToken,
		ResourceID:     "access",
		ResourceParent: h.auditService,
		ResourcePath:   h.auditService + "/token/access",
		Action:         "revoke",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"token_type_hint": typeHint,
		},
	})
}

// doRevoke calls the revoker and writes any necessary error response.
// Returns false only for genuine infrastructure failures (500 written).
// Token-not-found is treated as success per RFC 7009 §2.2.
func (h *Handler) doRevoke(w http.ResponseWriter, r *http.Request, token string) bool {
	err := h.revoker.Revoke(r.Context(), token)
	if err != nil && !apperrors.IsNotFound(err) {
		h.logger.Error("revocation failed", "error", err.Error())
		writeOAuthError(w, h.logger, "server_error", "revocation failed", http.StatusInternalServerError)
		return false
	}
	return true
}

// validateTokenTypeHint validates token_type_hint per RFC 7009 §2.2.
// Returns false and writes a 400 if the hint value is unrecognized.
// Known values (access_token, refresh_token, and empty) are accepted as advisory.
func (h *Handler) validateTokenTypeHint(w http.ResponseWriter, r *http.Request) bool {
	hint := r.FormValue("token_type_hint")
	if hint != "" && hint != "access_token" && hint != "refresh_token" {
		writeOAuthError(w, h.logger, unsupportedTokenType, "unsupported token type hint", http.StatusBadRequest)
		return false
	}
	return true
}

// Health handles GET /health.
//
// @Summary      Health check
// @Description  Returns service health status
// @Tags         health
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /health [get]
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// clientIP extracts the request's remote IP for rate-limiting.
// Strips the port if present.
func clientIP(r *http.Request) string {
	// Trust X-Forwarded-For only when deployed behind a known reverse proxy.
	// For the reference implementation, use the direct connection IP.
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i > 0 {
		ip = ip[:i]
	}
	return ip
}

// fixedWindowLimiter is a per-key fixed-window rate limiter.
// maxReqs requests are allowed per window; excess requests are rejected.
// Expired entries are evicted lazily on each window reset to prevent
// unbounded map growth under high cardinality of unique keys.
// Thread-safe via sync.Mutex.
type fixedWindowLimiter struct {
	mu      sync.Mutex
	buckets map[string]windowBucket
	maxReqs int
	window  time.Duration
}

type windowBucket struct {
	count int
	reset time.Time
}

func newFixedWindowLimiter(maxReqs int, window time.Duration) *fixedWindowLimiter {
	return &fixedWindowLimiter{
		buckets: make(map[string]windowBucket),
		maxReqs: maxReqs,
		window:  window,
	}
}

// Allow reports whether a request from key is within the rate limit.
func (l *fixedWindowLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok || now.After(b.reset) {
		// Evict all expired entries lazily to prevent unbounded map growth.
		for k, v := range l.buckets {
			if now.After(v.reset) {
				delete(l.buckets, k)
			}
		}
		l.buckets[key] = windowBucket{count: 1, reset: now.Add(l.window)}
		return true
	}
	if b.count >= l.maxReqs {
		return false
	}
	b.count++
	l.buckets[key] = b
	return true
}

// tokenIssuerAdapter adapts the grant registry to the TokenIssuer port.
// The indirection keeps the HTTP handler decoupled from the concrete registry type —
// handler tests can stub IssueToken without wiring a full GrantStrategyRegistry.
type tokenIssuerAdapter struct {
	registry *application.GrantStrategyRegistry
}

func NewTokenIssuerAdapter(registry *application.GrantStrategyRegistry) ports.TokenIssuer {
	return &tokenIssuerAdapter{registry: registry}
}

func (a *tokenIssuerAdapter) IssueToken(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error) {
	return a.registry.Handle(ctx, req)
}

// introspectorSvc is the narrow interface required by tokenIntrospectorAdapter.
// Defining it here (at the adapter boundary) keeps the adapter decoupled from
// the concrete application.TokenService type.
type introspectorSvc interface {
	Introspect(ctx context.Context, raw string) (*domain.IntrospectResponse, error)
}

// revokerSvc is the narrow interface required by tokenRevokerAdapter.
type revokerSvc interface {
	Revoke(ctx context.Context, raw string) error
}

// tokenIntrospectorAdapter adapts any introspectorSvc to the TokenIntrospector port.
// Using the narrow introspectorSvc interface (defined here, not in application/) avoids
// importing the concrete TokenService type into this adapter layer.
type tokenIntrospectorAdapter struct {
	svc introspectorSvc
}

func NewTokenIntrospectorAdapter(svc introspectorSvc) ports.TokenIntrospector {
	return &tokenIntrospectorAdapter{svc: svc}
}

func (a *tokenIntrospectorAdapter) Introspect(ctx context.Context, raw string) (*domain.IntrospectResponse, error) {
	return a.svc.Introspect(ctx, raw)
}

// tokenRevokerAdapter adapts any revokerSvc to the TokenRevoker port.
// Same decoupling rationale as tokenIntrospectorAdapter — see revokerSvc above.
type tokenRevokerAdapter struct {
	svc revokerSvc
}

func NewTokenRevokerAdapter(svc revokerSvc) ports.TokenRevoker {
	return &tokenRevokerAdapter{svc: svc}
}

func (a *tokenRevokerAdapter) Revoke(ctx context.Context, raw string) error {
	return a.svc.Revoke(ctx, raw)
}
