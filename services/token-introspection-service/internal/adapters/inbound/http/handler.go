package http

import (
	"net/http"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"

	// Imported for swagger doc generation.
	_ "github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/ports"
)

// Handler holds HTTP handler dependencies.
type Handler struct {
	introspector ports.Introspector
	logger       logging.Logger
}

func NewHandler(introspector ports.Introspector, logger logging.Logger) *Handler {
	return &Handler{introspector: introspector, logger: logger}
}

// Introspect handles POST /introspect.
//
// @Summary      Introspect token
// @Description  Validates a JWT token and returns metadata per RFC 7662
// @Tags         introspection
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        token  formData  string  true  "JWT token to introspect"
// @Success      200  {object}  domain.IntrospectionResult
// @Failure      400  {object}  httputil.ErrorResponse
// @Router       /introspect [post]
func (h *Handler) Introspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid request body"))
		return
	}

	raw := r.FormValue("token")
	if raw == "" {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "token parameter is required"))
		return
	}

	result, err := h.introspector.Introspect(r.Context(), raw)
	if err != nil {
		h.logger.Error("introspection failed", "error", err.Error())
		httputil.WriteError(w, err)
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
