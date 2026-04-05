package http

import (
	"net/http"

	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/ports"
)

// Ensure domain.IntrospectionResult is referenced so the package is included
// in Swagger doc generation scans.
var _ *domain.IntrospectionResult

// Handler holds HTTP handler dependencies.
type Handler struct {
	introspector ports.Introspector
	logger       logging.Logger
}

func NewHandler(introspector ports.Introspector, logger logging.Logger) *Handler {
	return &Handler{introspector: introspector, logger: logger}
}

// inactive is the RFC 7662 §2.2 response for any token that cannot be confirmed active.
var inactive = map[string]bool{"active": false}

// Introspect handles POST /introspect.
//
// Per RFC 7662 §2.2 this endpoint ALWAYS returns HTTP 200.
// Invalid, expired, revoked, or missing tokens return {"active": false}.
// A 400 is never appropriate here — the caller cannot distinguish a bad
// request from an invalid token without reading implementation details.
//
// @Summary      Introspect token
// @Description  Validates a JWT token and returns metadata per RFC 7662. Always returns HTTP 200.
// @Tags         introspection
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        token  formData  string  true  "JWT token to introspect"
// @Success      200  {object}  domain.IntrospectionResult
// @Router       /introspect [post]
func (h *Handler) Introspect(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		h.logger.Error("failed to parse introspect form", "error", err.Error())
		httputil.WriteJSON(w, http.StatusOK, inactive)
		return
	}

	raw := r.FormValue("token")
	if raw == "" {
		// Per RFC 7662 §2.2: a missing token cannot be active.
		httputil.WriteJSON(w, http.StatusOK, inactive)
		return
	}

	result, err := h.introspector.Introspect(r.Context(), raw)
	if err != nil {
		// Per RFC 7662 §2.2, infrastructure failures must not expose errors to the caller.
		// Log for observability, then return {active: false} (fail closed).
		h.logger.Error("introspection failed", "error", err.Error())
		httputil.WriteJSON(w, http.StatusOK, inactive)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, result)
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
