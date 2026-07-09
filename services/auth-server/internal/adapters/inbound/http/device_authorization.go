package http

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/httputil"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// userCodeAlphabet is the 32-symbol Crockford Base32 alphabet: digits 0-9
// plus uppercase letters excluding I, L, O, U — the letters most easily
// confused with a digit or with each other when a human re-types a code
// from one screen to another (RFC 8628 §6.1).
const userCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// DeviceAuthorizationHandler serves POST /device_authorization (RFC 8628
// §3.1, ADR-0022). Client authentication mirrors the token endpoint's
// ports.ClientAuthenticator.Authenticate call directly rather than
// readGrantClientCredentials — that helper hardcodes a non-empty-secret
// requirement that would incorrectly reject public clients, and device
// flow clients (CLIs, IoT) are frequently public.
type DeviceAuthorizationHandler struct {
	clientAuth      ports.ClientAuthenticator
	repo            domain.DeviceAuthorizationRepository
	verificationURI string
	ttl             time.Duration
	interval        int
	// serviceToken authenticates POST /internal/device/decision — the
	// same shared-secret model as auth-server's existing
	// /internal/issue-code (ADR-0011), reused here rather than inventing
	// a second bearer-token convention.
	serviceToken string
	logger       logging.Logger
}

// NewDeviceAuthorizationHandler wires the handler's dependencies.
// verificationURI is the absolute login-ui URL the client should display
// to the user (e.g. "https://login-ui.example.com/device"). serviceToken
// authenticates POST /internal/device/decision; when empty, that endpoint
// returns 404 (mirrors /internal/issue-code's own empty-token guard).
func NewDeviceAuthorizationHandler(
	clientAuth ports.ClientAuthenticator,
	repo domain.DeviceAuthorizationRepository,
	verificationURI string,
	ttl time.Duration,
	interval int,
	serviceToken string,
	logger logging.Logger,
) *DeviceAuthorizationHandler {
	return &DeviceAuthorizationHandler{
		clientAuth:      clientAuth,
		repo:            repo,
		verificationURI: verificationURI,
		ttl:             ttl,
		interval:        interval,
		serviceToken:    serviceToken,
		logger:          logger,
	}
}

// deviceAuthorizationResponse is the RFC 8628 §3.2 response shape.
type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// PostDeviceAuthorization handles POST /device_authorization.
//
// @Summary      Device authorization endpoint
// @Description  Starts an RFC 8628 device authorization grant (ADR-0022)
// @Tags         oauth
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        client_id      formData  string  true   "Client identifier"
// @Param        client_secret  formData  string  false  "Client secret (omitted for public clients)"
// @Param        scope          formData  string  false  "Requested scope"
// @Success      200  {object}  deviceAuthorizationResponse
// @Failure      400  {object}  httputil.ErrorResponse
// @Router       /device_authorization [post]
func (h *DeviceAuthorizationHandler) PostDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, h.logger, "invalid_request", "invalid form data", http.StatusBadRequest)
		return
	}
	clientID, clientSecret, ok := readDeviceAuthClientCredentials(w, r, h.logger)
	if !ok {
		return
	}
	client, err := h.clientAuth.Authenticate(r.Context(), clientID, clientSecret)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="auth-server"`)
		writeOAuthError(w, h.logger, "invalid_client", "client authentication failed", http.StatusUnauthorized)
		return
	}
	if !client.HasGrantType(domain.GrantTypeDeviceCode) {
		writeOAuthError(w, h.logger, "unauthorized_client", "grant type not allowed for client", http.StatusBadRequest)
		return
	}
	h.issueAndRespond(w, r, client, r.FormValue("scope"))
}

// issueAndRespond generates the device_code/user_code pair, persists the
// record, and writes the response. Extracted from PostDeviceAuthorization
// to keep its cyclomatic complexity within bounds.
func (h *DeviceAuthorizationHandler) issueAndRespond(w http.ResponseWriter, r *http.Request, client *domain.Client, scope string) {
	deviceCode, err := generateOpaqueDeviceCode()
	if err != nil {
		writeOAuthError(w, h.logger, "server_error", "internal server error", http.StatusInternalServerError)
		return
	}
	userCode, err := generateUserCode()
	if err != nil {
		writeOAuthError(w, h.logger, "server_error", "internal server error", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	auth := &domain.DeviceAuthorization{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   client.ID,
		Scope:      scope,
		Status:     domain.DeviceAuthorizationPending,
		Interval:   h.interval,
		CreatedAt:  now,
		ExpiresAt:  now.Add(h.ttl),
	}
	if err := h.repo.Save(r.Context(), auth); err != nil {
		h.logger.Error("device_authorization: save failed", "error", err.Error())
		writeOAuthError(w, h.logger, "server_error", "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	httputil.WriteJSON(w, http.StatusOK, deviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         h.verificationURI,
		VerificationURIComplete: h.verificationURI + "?user_code=" + url.QueryEscape(userCode),
		ExpiresIn:               int(h.ttl.Seconds()),
		Interval:                h.interval,
	})
}

// readDeviceAuthClientCredentials extracts client_id/client_secret from
// Basic Auth or form fields. Unlike readGrantClientCredentials, it does
// NOT enforce a non-empty secret — device flow clients are frequently
// public, and ports.ClientAuthenticator.Authenticate already distinguishes
// public from confidential clients correctly (ADR-0021's precedent for the
// same public-client requirement at the PAR endpoint).
func readDeviceAuthClientCredentials(w http.ResponseWriter, r *http.Request, logger logging.Logger) (string, string, bool) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}
	if clientID == "" {
		writeOAuthError(w, logger, "invalid_request", "client_id is required", http.StatusBadRequest)
		return "", "", false
	}
	return clientID, clientSecret, true
}

// generateOpaqueDeviceCode returns 32 bytes of CSPRNG entropy hex-encoded
// (64 hex chars, 256 bits) — the RFC 8628 §3.2 device_code value.
func generateOpaqueDeviceCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// generateUserCode returns an 8-character user_code drawn from
// userCodeAlphabet, formatted XXXX-XXXX for readability when a human
// re-types it from one screen to another (RFC 8628 §3.2, §6.1). The
// alphabet length (32) divides 256 evenly, so byte%32 introduces no
// modulo bias.
func generateUserCode() (string, error) {
	const length = 8
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := make([]byte, length)
	for i, v := range b {
		code[i] = userCodeAlphabet[int(v)%len(userCodeAlphabet)]
	}
	return string(code[:4]) + "-" + string(code[4:]), nil
}

// deviceDecisionRequest is the JSON body shape of
// POST /internal/device/decision.
type deviceDecisionRequest struct {
	UserCode string `json:"user_code"`
	Subject  string `json:"subject"`
	Approved bool   `json:"approved"`
}

type deviceDecisionResponse struct {
	Status string `json:"status"`
}

// PostDecision handles POST /internal/device/decision.
//
// login-ui calls this endpoint after the user has authenticated on the
// device verification page and clicked Approve or Deny. Authentication is
// a shared service bearer token (constant-time compare), identical to
// /internal/issue-code (ADR-0011) — this is NOT a user-facing endpoint and
// is not advertised in RFC 8414 metadata.
//
// @Summary      Device decision endpoint (internal)
// @Description  Records a user's approve/deny decision for a pending device authorization (ADR-0022)
// @Tags         internal
// @Accept       application/json
// @Produce      json
// @Success      200  {object}  deviceDecisionResponse
// @Failure      400  {object}  httputil.ErrorResponse
// @Failure      401  {object}  httputil.ErrorResponse
// @Router       /internal/device/decision [post]
func (h *DeviceAuthorizationHandler) PostDecision(w http.ResponseWriter, r *http.Request) {
	if h.serviceToken == "" {
		http.NotFound(w, r)
		return
	}
	if !h.verifyDecisionServiceBearer(r) {
		writeOAuthError(w, h.logger, "invalid_client", "service authentication failed", http.StatusUnauthorized)
		return
	}
	body, ok := decodeDeviceDecisionBody(w, r, h.logger)
	if !ok {
		return
	}
	if err := h.applyDecision(r, body); err != nil {
		writeOAuthError(w, h.logger, "invalid_request", "unknown or expired user_code", http.StatusBadRequest)
		return
	}
	status := "denied"
	if body.Approved {
		status = "approved"
	}
	httputil.WriteJSON(w, http.StatusOK, deviceDecisionResponse{Status: status})
}

// applyDecision calls Approve or Deny depending on body.Approved.
// Extracted from PostDecision to keep its cyclomatic complexity within
// bounds.
func (h *DeviceAuthorizationHandler) applyDecision(r *http.Request, body deviceDecisionRequest) error {
	if body.Approved {
		return h.repo.Approve(r.Context(), body.UserCode, body.Subject)
	}
	return h.repo.Deny(r.Context(), body.UserCode)
}

// decodeDeviceDecisionBody reads the JSON body, enforces the request size
// cap, and verifies the required fields. Writes the error response and
// returns false on any failure.
func decodeDeviceDecisionBody(w http.ResponseWriter, r *http.Request, logger logging.Logger) (deviceDecisionRequest, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var body deviceDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeOAuthError(w, logger, "invalid_request", "malformed json", http.StatusBadRequest)
		return body, false
	}
	if body.UserCode == "" {
		writeOAuthError(w, logger, "invalid_request", "user_code is required", http.StatusBadRequest)
		return body, false
	}
	if body.Approved && body.Subject == "" {
		writeOAuthError(w, logger, "invalid_request", "subject is required when approved is true", http.StatusBadRequest)
		return body, false
	}
	return body, true
}

// verifyDecisionServiceBearer validates the Authorization header against
// serviceToken using a constant-time comparison. Mirrors
// Handler.verifyServiceBearer exactly (ADR-0011's precedent) — kept as a
// separate method since DeviceAuthorizationHandler and Handler are
// distinct types with no shared base to hang a common implementation on.
func (h *DeviceAuthorizationHandler) verifyDecisionServiceBearer(r *http.Request) bool {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	presented := auth[len(prefix):]
	expected := h.serviceToken
	if len(presented) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
}
