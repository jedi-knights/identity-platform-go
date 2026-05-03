package http

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

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
}

func NewHandler(
	issuer ports.TokenIssuer,
	introspector ports.TokenIntrospector,
	revoker ports.TokenRevoker,
	clientAuth ports.ClientAuthenticator,
	logger logging.Logger,
	introspectionSecret string,
) *Handler {
	return &Handler{
		issuer:              issuer,
		introspector:        introspector,
		revoker:             revoker,
		clientAuth:          clientAuth,
		logger:              logger,
		introspectionSecret: introspectionSecret,
		rateLimiter:         newFixedWindowLimiter(20, time.Minute),
	}
}

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
func writeTokenError(w http.ResponseWriter, logger logging.Logger, err error) {
	if errors.Is(err, application.ErrUnsupportedGrantType) {
		writeOAuthError(w, logger, "unsupported_grant_type", "grant type not supported", http.StatusBadRequest)
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

// Authorize handles GET /oauth/authorize (stub).
//
// @Summary      Authorization endpoint
// @Description  Authorization endpoint - not yet implemented
// @Tags         oauth
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /oauth/authorize [get]
func (h *Handler) Authorize(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not yet implemented", http.StatusNotImplemented)
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

	if !h.authenticateIntrospectionCaller(w, r) {
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

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	httputil.WriteJSON(w, http.StatusOK, resp)
}

// authenticateIntrospectionCaller enforces RFC 7662 §2.1 caller authentication.
// When introspectionSecret is set: require Authorization: Bearer <secret>.
// Otherwise: require client credentials (Basic Auth or form body).
// Returns false and writes a 401 if authentication fails.
func (h *Handler) authenticateIntrospectionCaller(w http.ResponseWriter, r *http.Request) bool {
	if h.introspectionSecret != "" {
		return authenticateWithSecret(w, r, h.introspectionSecret, h.logger)
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
// Returns false and writes a 401 WWW-Authenticate challenge if credentials are missing or invalid.
func (h *Handler) authenticateClientCredentials(w http.ResponseWriter, r *http.Request) bool {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}
	if clientID == "" || clientSecret == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="auth-server"`)
		writeOAuthError(w, h.logger, "invalid_client", "client authentication required", http.StatusUnauthorized)
		return false
	}
	if _, err := h.clientAuth.Authenticate(r.Context(), clientID, clientSecret); err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="auth-server"`)
		writeOAuthError(w, h.logger, "invalid_client", "client authentication failed", http.StatusUnauthorized)
		return false
	}
	return true
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
	if !h.authenticateClientCredentials(w, r) {
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

	// Success path: all error paths above return early.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
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
// Returns false and writes a 400 if the hint value is unrecognised.
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
