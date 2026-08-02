package http

import (
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// signUpView is the data the sign-up template renders against. Name /
// Email echo prior form input so a POST failure re-renders the form
// with the user's values preserved (they only re-type the password,
// which the browser never surfaces as a plain-text hidden field).
type signUpView struct {
	Name  string
	Email string
	Error string
}

// SignUpGet renders the sign-up form. Returns 503 when the registrar
// adapter is unwired — matches how the sign-in / billing routes
// degrade in environments without identity-service configured.
//
// @Summary      Render sign-up page
// @Description  Renders the account-creation form; on submit the user is bounced to /billing/plans to pick a plan
// @Tags         signup
// @Produce      html
// @Success      200  "HTML form"
// @Failure      503  "Sign-up not configured"
// @Router       /sign-up [get]
func (h *Handler) SignUpGet(w http.ResponseWriter, _ *http.Request) {
	if !h.signUpWired(w) {
		return
	}
	h.renderSignUp(w, signUpView{})
}

// SignUpPost processes the sign-up form. Order of operations:
//  1. Parse and validate form fields (client-side required= is not
//     enough — a curl caller can skip them).
//  2. Register against identity-service via the outbound port.
//  3. Redirect to /billing/plans?subject=<user_id> so the freshly-
//     created user picks a plan (E5-S2 fills in the provisioning
//     side of that selection; E5-S1 delivers the entry point).
//
// The subject query parameter is the interim identity bridge the
// existing /billing/plans handler already reads — same convention
// /billing/portal and /accounts (E7-S3d) use. Replaced once login-ui
// owns a signed session.
//
// Failure surfaces as an inline error on the form (not a 5xx), so
// the user can correct their input without losing their name/email.
//
// @Summary      Submit sign-up
// @Description  Creates the user account and redirects to the plan picker
// @Tags         signup
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        name      formData  string  true  "Full name"
// @Param        email     formData  string  true  "Email address"
// @Param        password  formData  string  true  "Password"
// @Success      302  "Redirect to /billing/plans"
// @Failure      200  "HTML form re-rendered with inline error"
// @Failure      400  "Malformed form"
// @Failure      503  "Sign-up not configured"
// @Router       /sign-up [post]
func (h *Handler) SignUpPost(w http.ResponseWriter, r *http.Request) {
	if !h.signUpWired(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	view := signUpView{
		Name:  r.PostForm.Get("name"),
		Email: r.PostForm.Get("email"),
	}
	password := r.PostForm.Get("password")
	if view.Name == "" || view.Email == "" || password == "" {
		view.Error = "Name, email, and password are all required."
		h.renderSignUp(w, view)
		return
	}
	result, err := h.registrar.Register(r.Context(), ports.RegisterRequest{
		Name:     view.Name,
		Email:    view.Email,
		Password: password,
	})
	if err != nil {
		h.renderSignUp(w, view.withRegisterError(err))
		return
	}
	// Bounce to the existing plan picker with the fresh subject and
	// account id. account is used as the Lago external_customer_id
	// per E5-S2; subject stays for log correlation until login-ui
	// owns a signed session.
	http.Redirect(w, r, plansRedirectURL(result), http.StatusFound)
}

// plansRedirectURL composes the post-signup redirect target. Extracted
// so SignUpPost stays under the gocyclo budget; a nil result is not
// possible in practice but the helper is defensive so a future refactor
// can call it from other paths without a panic risk.
func plansRedirectURL(result *ports.RegisterResult) string {
	target := "/billing/plans?subject=" + result.UserID
	if result.AccountID != "" {
		target += "&account=" + result.AccountID
	}
	return target
}

// signUpWired guards both routes so the handler degrades gracefully
// when the registrar adapter is nil (identity-service unwired,
// LOGIN_UI_IDENTITY_SERVICE_URL not set).
func (h *Handler) signUpWired(w http.ResponseWriter) bool {
	if h.registrar == nil {
		http.Error(w, "sign-up not configured", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// renderSignUp writes the sign-up page. Template execution failures
// are logged but not surfaced — the response has already started
// streaming by the time Execute can fail.
func (h *Handler) renderSignUp(w http.ResponseWriter, view signUpView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := signUpTemplate.Execute(w, view); err != nil {
		h.logger.Error("sign-up: template execution failed", "error", err)
	}
}

// withRegisterError maps the outbound-port error to a user-safe
// message. The three cases the Registrar's parseRegisterResponse
// emits (conflict / bad-request / internal) each get a form-visible
// string; unexpected shapes fall through to the generic error so a
// leaky underlying message never reaches the page.
func (v signUpView) withRegisterError(err error) signUpView {
	switch {
	case apperrors.IsConflict(err):
		v.Error = "An account with that email already exists. Try signing in instead."
	case apperrors.IsBadRequest(err):
		v.Error = "Please check your name, email, and password and try again."
	default:
		v.Error = "We couldn't create your account. Please try again."
	}
	return v
}
