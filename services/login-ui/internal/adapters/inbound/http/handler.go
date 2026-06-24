// Package http hosts the inbound HTTP surface for login-ui — the user-
// facing /sign-in screen (added in ADR-0011), the operational /health
// endpoint, and the /sign-up + /consent screens that land in follow-up
// commits.
package http

import (
	"embed"
	"html/template"
	"net/http"
	"net/url"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/httputil"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

//go:embed templates/sign-in.html
var templateFS embed.FS

// signInTemplate is parsed once at package init so each request renders
// without re-parsing. Failing at init keeps a malformed template from
// reaching production silently.
var signInTemplate = template.Must(template.ParseFS(templateFS, "templates/sign-in.html"))

// Handler bundles every HTTP handler login-ui owns. When userAuth and
// codeIssuer are nil the sign-in routes return 503 — letting /health remain
// reachable in environments where the outbound dependencies are not yet
// wired (compose smoke-tests, integration scaffolding).
type Handler struct {
	userAuth   ports.UserAuthenticator
	codeIssuer ports.AuthCodeIssuer
	logger     logging.Logger
}

// NewHandler returns a Handler wired with the outbound dependencies the
// sign-in flow needs. Either or both of userAuth and codeIssuer may be nil
// during local-only development; in that case the sign-in routes serve a
// stable 503 and /health continues to work.
func NewHandler(userAuth ports.UserAuthenticator, codeIssuer ports.AuthCodeIssuer, logger logging.Logger) *Handler {
	return &Handler{userAuth: userAuth, codeIssuer: codeIssuer, logger: logger}
}

// Health serves GET /health with a stable 200 + tiny JSON body so the
// docker-compose healthcheck and any orchestration probe can verify the
// process is up.
//
// @Summary      Health check
// @Description  Process liveness probe
// @Tags         health
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /health [get]
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// signInView is the data the sign-in template renders against. Error is
// the only non-trivial field — populated when a prior POST failed so the
// user can correct their entry without losing the challenge.
type signInView struct {
	LoginChallenge string
	Error          string
}

// SignInGet renders the sign-in form. The login_challenge query parameter
// is required — a missing or empty value means the user landed on /sign-in
// outside an OAuth flow, which is a programming or routing error and
// surfaces as a 400.
//
// @Summary      Render sign-in page
// @Description  Renders the platform-wide sign-in form for ADR-0011 login
// @Tags         signin
// @Produce      html
// @Param        login_challenge  query  string  true  "Opaque login-challenge ID from auth-server"
// @Success      200  "HTML form"
// @Failure      400  "Missing login_challenge"
// @Router       /sign-in [get]
func (h *Handler) SignInGet(w http.ResponseWriter, r *http.Request) {
	if !h.signInWired(w) {
		return
	}
	loginChallenge := r.URL.Query().Get("login_challenge")
	if loginChallenge == "" {
		http.Error(w, "missing login_challenge", http.StatusBadRequest)
		return
	}
	h.renderSignIn(w, signInView{LoginChallenge: loginChallenge})
}

// SignInPost processes the sign-in form. Order of operations:
//  1. Parse and validate form fields.
//  2. Verify credentials against identity-service.
//  3. Call auth-server /internal/issue-code to redeem the challenge.
//  4. 302 to the RP's redirect_uri with ?code=&state=.
//
// Steps 2 and 3 each fail-closed: the user sees a generic "invalid email
// or password" on credential failure and a generic "could not complete
// sign-in" on infrastructure failure.
//
// @Summary      Submit sign-in
// @Description  Authenticates the user and redirects back to the relying party
// @Tags         signin
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        login_challenge  formData  string  true  "Login challenge ID"
// @Param        email            formData  string  true  "User email"
// @Param        password         formData  string  true  "User password"
// @Success      302  "Redirect to relying party"
// @Failure      400  "Missing fields"
// @Router       /sign-in [post]
func (h *Handler) SignInPost(w http.ResponseWriter, r *http.Request) {
	if !h.signInWired(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	loginChallenge := r.PostForm.Get("login_challenge")
	email := r.PostForm.Get("email")
	password := r.PostForm.Get("password")
	if loginChallenge == "" || email == "" || password == "" {
		h.renderSignIn(w, signInView{LoginChallenge: loginChallenge, Error: "email, password and login_challenge are required"})
		return
	}
	subject, err := h.userAuth.VerifyCredentials(r.Context(), email, password)
	if err != nil {
		h.signInError(w, loginChallenge, err)
		return
	}
	h.redeemAndRedirect(w, r, loginChallenge, subject)
}

// signInWired guards both routes so the handler can degrade gracefully when
// either outbound dependency is nil.
func (h *Handler) signInWired(w http.ResponseWriter) bool {
	if h.userAuth == nil || h.codeIssuer == nil {
		http.Error(w, "sign-in not configured", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// renderSignIn writes the sign-in page. Errors writing the template are
// logged but not returned to the user — there is nothing meaningful the
// caller can do with a half-written response.
func (h *Handler) renderSignIn(w http.ResponseWriter, view signInView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := signInTemplate.Execute(w, view); err != nil {
		h.logger.Error("sign-in: template execution failed", "error", err)
	}
}

// signInError maps the VerifyCredentials error to a user-safe message and
// re-renders the form so the user can retry without losing the challenge.
func (h *Handler) signInError(w http.ResponseWriter, loginChallenge string, err error) {
	if apperrors.IsUnauthorized(err) {
		h.renderSignIn(w, signInView{LoginChallenge: loginChallenge, Error: "invalid email or password"})
		return
	}
	h.logger.Error("sign-in: credential verification failed", "error", err)
	h.renderSignIn(w, signInView{LoginChallenge: loginChallenge, Error: "could not complete sign-in"})
}

// redeemAndRedirect calls auth-server's /internal/issue-code and bounces the
// user-agent to the RP. RedirectURI and State come from auth-server's
// response, which itself sourced them from the server-side LoginChallenge —
// login-ui never trusts the form body for either value.
func (h *Handler) redeemAndRedirect(w http.ResponseWriter, r *http.Request, loginChallenge, subject string) {
	resp, err := h.codeIssuer.IssueCode(r.Context(), ports.IssueCodeRequest{
		LoginChallenge: loginChallenge,
		SessionID:      subject,
		// Consent is wired up in the follow-up commit. For now request the
		// full scope set the challenge already records by sending nil —
		// auth-server treats nil as "grant the recorded scopes".
		ConsentGranted: nil,
	})
	if err != nil {
		h.logger.Error("sign-in: issue-code failed", "error", err)
		h.renderSignIn(w, signInView{LoginChallenge: loginChallenge, Error: "could not complete sign-in"})
		return
	}
	target, err := url.Parse(resp.RedirectURI)
	if err != nil {
		h.logger.Error("sign-in: malformed redirect_uri", "error", err)
		http.Error(w, "could not complete sign-in", http.StatusInternalServerError)
		return
	}
	q := target.Query()
	q.Set("code", resp.Code)
	if resp.State != "" {
		q.Set("state", resp.State)
	}
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

