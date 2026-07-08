package http

import (
	"net/http"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/httputil"
)

// NewRouter builds the login-ui HTTP mux and wraps it with the standard
// trace-id / logging / recovery middleware chain. Outermost-first ordering
// matches the rest of the platform's services: Recovery wraps Logging
// wraps TraceID so a panic surfaces a structured 500 with a trace id
// already attached.
func NewRouter(h *Handler, logger logging.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", h.Health)
	mux.HandleFunc("GET /sign-in", h.SignInGet)
	mux.HandleFunc("POST /sign-in", h.SignInPost)
	mux.HandleFunc("GET /device", h.DeviceGet)
	mux.HandleFunc("POST /device", h.DevicePost)
	mux.HandleFunc("GET /billing/plans", h.PlansGet)
	mux.HandleFunc("POST /billing/checkout", h.CheckoutPost)
	mux.HandleFunc("GET /billing/portal", h.PortalGet)

	return httputil.RecoveryMiddleware(logger)(
		httputil.LoggingMiddleware(logger)(
			httputil.TraceIDMiddleware(mux),
		),
	)
}
