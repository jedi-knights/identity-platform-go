// Package http hosts the inbound HTTP surface for login-ui — the user-
// facing /sign-in, /sign-up, /consent and /sign-out screens (added in
// subsequent ADR-0011 commits) plus operational endpoints like /health.
package http

import (
	"net/http"

	"github.com/jedi-knights/go-platform/httputil"
)

// Handler bundles every HTTP handler login-ui owns. Right now it holds
// nothing — once the sign-in flow lands the handler picks up its outbound
// dependencies (identity-service client, auth-server /internal/issue-code
// client, session store).
type Handler struct{}

// NewHandler returns an empty Handler. Kept as a constructor (rather than
// a plain struct literal at the wiring site) so future fields can be added
// without touching the container.
func NewHandler() *Handler {
	return &Handler{}
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
