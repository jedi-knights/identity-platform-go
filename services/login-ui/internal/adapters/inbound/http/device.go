package http

import (
	"html/template"
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// deviceTemplate renders the RFC 8628 device verification page (ADR-0022).
// Parsed once at init for the same reason as signInTemplate.
var deviceTemplate = template.Must(template.ParseFS(templateFS, "templates/device.html"))

// deviceView is the data the device template renders against.
type deviceView struct {
	UserCode string
	Error    string
	// Message is set on success; the template shows this instead of the
	// form since there is nothing further for the user to do — the device
	// is polling auth-server independently.
	Message string
}

// WithDeviceDecider wires the [ports.DeviceDecider] outbound port. Returns
// the receiver to allow chained construction at the composition root,
// matching [Handler.WithBilling]'s pattern. Passing nil leaves /device
// degraded (503), same as the sign-in routes when their dependencies are
// nil.
func (h *Handler) WithDeviceDecider(decider ports.DeviceDecider) *Handler {
	h.deviceDecider = decider
	return h
}

// DeviceGet renders the device verification form. The user_code query
// parameter pre-fills the field — the value a client displays via
// verification_uri_complete (RFC 8628 §3.3.1) lands here.
//
// @Summary      Render device verification page
// @Description  Renders the RFC 8628 device verification form (ADR-0022)
// @Tags         device
// @Produce      html
// @Param        user_code  query  string  false  "Pre-filled user_code from verification_uri_complete"
// @Success      200  "HTML form"
// @Failure      503  "Device verification not configured"
// @Router       /device [get]
func (h *Handler) DeviceGet(w http.ResponseWriter, r *http.Request) {
	if !h.deviceWired(w) {
		return
	}
	h.renderDevice(w, deviceView{UserCode: r.URL.Query().Get("user_code")})
}

// DevicePost processes the device verification form. Denying does not
// require credentials — only approving binds a subject to the request, so
// only the approve path authenticates.
//
// @Summary      Submit device verification decision
// @Description  Authenticates the user (on approve) and records the decision with auth-server
// @Tags         device
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        user_code  formData  string  true   "Device user_code"
// @Param        email      formData  string  false  "User email (required to approve)"
// @Param        password   formData  string  false  "User password (required to approve)"
// @Param        decision   formData  string  true   "approve or deny"
// @Success      200  "HTML confirmation or re-rendered form with error"
// @Failure      503  "Device verification not configured"
// @Router       /device [post]
func (h *Handler) DevicePost(w http.ResponseWriter, r *http.Request) {
	if !h.deviceWired(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	userCode, decision, ok := validateDeviceDecisionForm(r)
	if !ok {
		h.renderDevice(w, deviceView{UserCode: userCode, Error: "code and a valid decision are required"})
		return
	}
	if decision == "deny" {
		h.applyDeviceDecision(w, r, userCode, "", false)
		return
	}
	h.approveDevice(w, r, userCode)
}

// validateDeviceDecisionForm extracts and validates user_code and decision.
// Extracted from DevicePost to keep its cyclomatic complexity within
// bounds.
func validateDeviceDecisionForm(r *http.Request) (userCode, decision string, ok bool) {
	userCode = r.PostForm.Get("user_code")
	decision = r.PostForm.Get("decision")
	if userCode == "" {
		return userCode, decision, false
	}
	if decision != "approve" && decision != "deny" {
		return userCode, decision, false
	}
	return userCode, decision, true
}

// approveDevice verifies credentials and, on success, applies the approval.
// Extracted from DevicePost to keep its cyclomatic complexity within
// bounds.
func (h *Handler) approveDevice(w http.ResponseWriter, r *http.Request, userCode string) {
	email := r.PostForm.Get("email")
	password := r.PostForm.Get("password")
	if email == "" || password == "" {
		h.renderDevice(w, deviceView{UserCode: userCode, Error: "email and password are required to approve"})
		return
	}
	subject, err := h.userAuth.VerifyCredentials(r.Context(), email, password)
	if err != nil {
		h.deviceCredentialError(w, userCode, err)
		return
	}
	h.applyDeviceDecision(w, r, userCode, subject, true)
}

// applyDeviceDecision calls the DeviceDecider and renders the outcome.
func (h *Handler) applyDeviceDecision(w http.ResponseWriter, r *http.Request, userCode, subject string, approved bool) {
	err := h.deviceDecider.Decide(r.Context(), ports.DeviceDecisionRequest{
		UserCode: userCode,
		Subject:  subject,
		Approved: approved,
	})
	if err != nil {
		h.logger.Error("device: decision call failed", "error", err)
		h.renderDevice(w, deviceView{UserCode: userCode, Error: "could not complete device authorization"})
		return
	}
	message := "Device denied."
	if approved {
		message = "Device approved — you can return to your device."
	}
	h.renderDevice(w, deviceView{Message: message})
}

// deviceCredentialError maps VerifyCredentials' error to a user-safe
// message and re-renders the form so the user can retry.
func (h *Handler) deviceCredentialError(w http.ResponseWriter, userCode string, err error) {
	if apperrors.IsUnauthorized(err) {
		h.renderDevice(w, deviceView{UserCode: userCode, Error: "invalid email or password"})
		return
	}
	h.logger.Error("device: credential verification failed", "error", err)
	h.renderDevice(w, deviceView{UserCode: userCode, Error: "could not complete device authorization"})
}

// deviceWired guards both routes so the handler can degrade gracefully
// when either outbound dependency is nil.
func (h *Handler) deviceWired(w http.ResponseWriter) bool {
	if h.userAuth == nil || h.deviceDecider == nil {
		http.Error(w, "device verification not configured", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// renderDevice writes the device verification page. Errors writing the
// template are logged but not returned to the user.
func (h *Handler) renderDevice(w http.ResponseWriter, view deviceView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := deviceTemplate.Execute(w, view); err != nil {
		h.logger.Error("device: template execution failed", "error", err)
	}
}
