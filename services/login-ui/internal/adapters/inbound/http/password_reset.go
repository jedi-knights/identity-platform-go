package http

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/jedi-knights/go-platform/apperrors"
)

// forgotPasswordTemplate and resetPasswordTemplate are parsed once at init,
// like their siblings, so a malformed template fails at startup.
var (
	forgotPasswordTemplate = template.Must(template.ParseFS(templateFS, "templates/forgot-password.html"))
	resetPasswordTemplate  = template.Must(template.ParseFS(templateFS, "templates/reset-password.html"))
)

// forgotPasswordView is the data the forgot-password template renders.
// LoginChallenge is carried only so the page can link back to the in-flight
// sign-in; the emailed reset link cannot carry it, so it ends here.
type forgotPasswordView struct {
	Email          string
	LoginChallenge string
	Error          string
	Sent           bool
}

// resetPasswordView is the data the reset-password template renders. Token
// is empty when the link is unusable (missing or already rejected), which
// hides the form; OfferNewLink adds a "request a new link" pointer. Passwords
// are deliberately not part of the view, so they can never be echoed back.
type resetPasswordView struct {
	Token        string
	Error        string
	OfferNewLink bool
	Done         bool
}

// ForgotPasswordGet renders the "email me a reset link" form.
//
// @Summary      Render forgot-password page
// @Tags         password-reset
// @Produce      html
// @Success      200  "HTML form"
// @Failure      503  "Password reset not configured"
// @Router       /forgot-password [get]
func (h *Handler) ForgotPasswordGet(w http.ResponseWriter, r *http.Request) {
	if !h.passwordResetWired(w) {
		return
	}
	h.renderForgotPassword(w, http.StatusOK, forgotPasswordView{LoginChallenge: r.URL.Query().Get("login_challenge")})
}

// ForgotPasswordPost asks identity-service to send a reset link. A success
// page is shown whether or not the address has an account, because the
// upstream never says; only a rate limit or an upstream failure changes what
// the user sees, and neither depends on the address.
//
// @Summary      Request a password-reset email
// @Tags         password-reset
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        email  formData  string  true  "Email address"
// @Success      200  "Confirmation page, or the form re-rendered with an inline error"
// @Failure      429  "Too many requests"
// @Failure      503  "Password reset not configured"
// @Router       /forgot-password [post]
func (h *Handler) ForgotPasswordPost(w http.ResponseWriter, r *http.Request) {
	if !h.passwordResetWired(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	view := forgotPasswordView{
		Email:          strings.TrimSpace(r.PostForm.Get("email")),
		LoginChallenge: r.PostForm.Get("login_challenge"),
	}
	if view.Email == "" {
		view.Error = "Enter your email address."
		h.renderForgotPassword(w, http.StatusOK, view)
		return
	}
	if err := h.passwordReset.RequestReset(r.Context(), view.Email); err != nil {
		status := h.forgotPasswordFailure(&view, err)
		h.renderForgotPassword(w, status, view)
		return
	}
	view.Sent = true
	h.renderForgotPassword(w, http.StatusOK, view)
}

// forgotPasswordFailure sets a user-safe message on view for err and returns
// the HTTP status to respond with. Upstream detail never reaches the page.
func (h *Handler) forgotPasswordFailure(view *forgotPasswordView, err error) int {
	switch {
	case apperrors.IsRateLimit(err):
		view.Error = "Too many requests. Please wait a while before trying again."
		return http.StatusTooManyRequests
	case apperrors.IsBadRequest(err):
		view.Error = "Enter a valid email address."
	default:
		h.logger.Error("forgot-password: request failed", "error", err.Error())
		view.Error = "We couldn't send the reset link. Please try again."
	}
	return http.StatusOK
}

// ResetPasswordGet renders the new-password form for the token in the
// emailed link. The token rides in the URL, so the response forbids
// referrers and caching to keep it from leaking onward.
//
// @Summary      Render reset-password page
// @Tags         password-reset
// @Produce      html
// @Param        token  query  string  true  "Reset token from the email link"
// @Success      200  "HTML form"
// @Failure      400  "Missing token"
// @Failure      503  "Password reset not configured"
// @Router       /reset-password [get]
func (h *Handler) ResetPasswordGet(w http.ResponseWriter, r *http.Request) {
	if !h.passwordResetWired(w) {
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		h.renderResetPassword(w, http.StatusBadRequest, incompleteLinkView())
		return
	}
	h.renderResetPassword(w, http.StatusOK, resetPasswordView{Token: token})
}

// ResetPasswordPost validates the form, then redeems the token. The
// passwords never appear in the response; the token is kept on retryable
// failures so the user does not have to reopen the email.
//
// @Summary      Set a new password
// @Tags         password-reset
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        token             formData  string  true  "Reset token"
// @Param        password          formData  string  true  "New password"
// @Param        confirm_password  formData  string  true  "New password, again"
// @Success      200  "Confirmation page, or the form re-rendered with an inline error"
// @Failure      400  "Malformed form, or missing token"
// @Failure      429  "Too many requests"
// @Failure      503  "Password reset not configured"
// @Router       /reset-password [post]
func (h *Handler) ResetPasswordPost(w http.ResponseWriter, r *http.Request) {
	if !h.passwordResetWired(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	token := r.PostForm.Get("token")
	password := r.PostForm.Get("password")
	if view, ok := validateResetForm(token, password, r.PostForm.Get("confirm_password")); !ok {
		h.renderResetPassword(w, http.StatusOK, view)
		return
	}
	if err := h.passwordReset.ResetPassword(r.Context(), token, password); err != nil {
		view, status := h.resetPasswordFailure(token, err)
		h.renderResetPassword(w, status, view)
		return
	}
	h.renderResetPassword(w, http.StatusOK, resetPasswordView{Done: true})
}

// validateResetForm checks the form before any upstream call. When ok is
// false, view is the page to re-render.
func validateResetForm(token, password, confirm string) (view resetPasswordView, ok bool) {
	switch {
	case token == "":
		return incompleteLinkView(), false
	case password == "":
		return resetPasswordView{Token: token, Error: "Enter a new password."}, false
	case password != confirm:
		return resetPasswordView{Token: token, Error: "The two passwords don't match."}, false
	}
	return resetPasswordView{}, true
}

// resetPasswordFailure maps an upstream error to the page to re-render and
// its HTTP status. A rejected token drops the form (it can never work
// again); every other failure keeps the token so the user can retry.
func (h *Handler) resetPasswordFailure(token string, err error) (resetPasswordView, int) {
	switch {
	case apperrors.IsUnauthorized(err):
		return resetPasswordView{Error: "This reset link is invalid or has expired.", OfferNewLink: true}, http.StatusOK
	case apperrors.IsBadRequest(err):
		return resetPasswordView{Token: token, Error: "That password doesn't meet the requirements. Try a longer one."}, http.StatusOK
	case apperrors.IsRateLimit(err):
		return resetPasswordView{Token: token, Error: "Too many attempts. Please wait a while and try again."}, http.StatusTooManyRequests
	}
	h.logger.Error("reset-password: redeem failed", "error", err.Error())
	return resetPasswordView{Token: token, Error: "We couldn't reset your password. Please try again."}, http.StatusOK
}

func incompleteLinkView() resetPasswordView {
	return resetPasswordView{Error: "This password reset link is incomplete.", OfferNewLink: true}
}

// passwordResetWired degrades to 503 when identity-service is unwired,
// matching sign-up and the other outbound-dependent routes.
func (h *Handler) passwordResetWired(w http.ResponseWriter) bool {
	if h.passwordReset == nil {
		http.Error(w, "password reset not configured", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func (h *Handler) renderForgotPassword(w http.ResponseWriter, status int, view forgotPasswordView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := forgotPasswordTemplate.Execute(w, view); err != nil {
		h.logger.Error("forgot-password: template execution failed", "error", err)
	}
}

// renderResetPassword writes the reset page. The URL carries the token, so
// the page opts out of referrers and caching.
func (h *Handler) renderResetPassword(w http.ResponseWriter, status int, view resetPasswordView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	if err := resetPasswordTemplate.Execute(w, view); err != nil {
		h.logger.Error("reset-password: template execution failed", "error", err)
	}
}
