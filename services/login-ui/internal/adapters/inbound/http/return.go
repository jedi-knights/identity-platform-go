package http

import (
	"html/template"
	"net/http"
)

// returnLandingTemplate is the fallback landing page /billing/return
// renders when no valid return_to was supplied. Kept intentionally
// small — the "originating app" flow is E5-S4's happy path; this page
// exists so a link-clicked-directly or invalid-return_to user still
// lands on a coherent success screen.
var returnLandingTemplate = template.Must(template.New("return").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>All set</title></head>
<body>
<h1>All set.</h1>
<p>Your account is provisioned. You can return to the app you started
from at any time.</p>
</body>
</html>`))

// ReturnGet handles GET /billing/return — the E5-S4 completion hop for
// the post-provisioning flow. Reads the return_to query parameter, and
// if the URL passes the host-allowlist validator, 302s the user back
// to the originating app. Otherwise renders a plain landing page so
// the user still sees a coherent success screen.
//
// The validator is invoked here as *defence in depth*: CheckoutPost
// already validates before embedding return_to into Stripe's success
// URL, but a user with a bookmarked or shared /billing/return URL
// could otherwise bypass the earlier check. Failing closed on this
// second hop is what prevents an open-redirect vulnerability.
//
// @Summary      Complete provisioning and return to originating app
// @Description  Validates return_to and 302s to it; renders a landing page when return_to is missing or unlisted.
// @Tags         billing
// @Produce      html
// @Param        return_to  query  string  false  "Originating-app return URL"
// @Success      200  "Landing page"
// @Success      302  "Redirect to return_to"
// @Router       /billing/return [get]
func (h *Handler) ReturnGet(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	if h.returnValidator != nil {
		if target, ok := h.returnValidator.Validate(returnTo); ok {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
	}
	h.renderReturnLanding(w)
}

// renderReturnLanding writes the fallback landing page. Errors are
// logged but not surfaced — the response has already started streaming
// by the time Execute can fail.
func (h *Handler) renderReturnLanding(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := returnLandingTemplate.Execute(w, nil); err != nil {
		h.logger.Error("billing/return: template execution failed", "error", err)
	}
}
