package http

import (
	"net/http"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/httpmw"
	"github.com/jedi-knights/go-platform/httpserver"
)

// NewRouter builds the entitlements-service HTTP router. Uses stdlib
// http.ServeMux — same pattern as other services in this monorepo. The
// method-prefixed pattern syntax (Go 1.22+) returns 405 automatically
// when the path matches but the method doesn't. The mux is wrapped with
// httpmw.Stack (request ID, trace ID, panic recovery, access logging).
func NewRouter(h *Handler, logger logging.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /accounts/personal", h.CreatePersonalAccount)
	mux.HandleFunc("POST /accounts/{account_id}/invites", h.CreateInvite)
	mux.HandleFunc("GET /users/{user_id}/seats", h.ListUserSeats)
	mux.HandleFunc("DELETE /accounts/{account_id}/seats/{user_id}", h.RemoveSeat)
	mux.HandleFunc("POST /accounts/{account_id}/transfer-ownership", h.TransferOwnership)
	mux.HandleFunc("POST /accounts/{account_id}/plans", h.ActivatePlan)
	mux.Handle("GET /health", httpserver.HealthHandler())
	return httpmw.Stack(logger)(mux)
}
