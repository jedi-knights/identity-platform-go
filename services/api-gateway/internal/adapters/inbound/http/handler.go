package http

import (
	"errors"
	"net/http"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/application"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// Handler holds all inbound HTTP handler dependencies.
// It is intentionally thin: each method extracts the minimum set of attributes
// from the *http.Request, delegates decisions to ports, and writes the response.
type Handler struct {
	router    ports.RequestRouter
	transport ports.UpstreamTransport
	metrics   ports.MetricsRecorder
	logger    logging.Logger
}

// NewHandler creates a Handler with the provided port implementations.
func NewHandler(
	router ports.RequestRouter,
	transport ports.UpstreamTransport,
	metrics ports.MetricsRecorder,
	logger logging.Logger,
) *Handler {
	return &Handler{
		router:    router,
		transport: transport,
		metrics:   metrics,
		logger:    logger,
	}
}

// Proxy is the catch-all HTTP handler that resolves a route and forwards the
// request to the upstream service. It is registered as the "/" handler so that
// every non-system path passes through it.
//
// @Summary      Proxy request to upstream
// @Description  Resolves the upstream route and forwards the request
// @Tags         proxy
// @Success      200  "Proxied response from upstream"
// @Failure      404  {object}  httputil.ErrorResponse
// @Failure      500  {object}  httputil.ErrorResponse
// @Router       / [get]
func (h *Handler) Proxy(w http.ResponseWriter, r *http.Request) {
	headers := extractHeaders(r)

	route, err := h.router.Route(r.Context(), r.Method, r.URL.Path, headers)
	if err != nil {
		if errors.Is(err, application.ErrNoRouteMatched) {
			httputil.WriteError(w, apperrors.New(apperrors.ErrCodeNotFound, "no route matched"))
			return
		}
		h.logger.Error("routing failed", "method", r.Method, "path", r.URL.Path, "error", err)
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "routing failed"))
		return
	}

	rw := newStatusRecorder(w)
	start := time.Now()

	if err := h.transport.Forward(rw, r, route); err != nil {
		h.logger.Error("upstream error", "route", route.Name, "error", err)
		if !rw.Written() {
			httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "upstream error"))
		}
		return
	}

	h.metrics.RecordRequest(route.Name, rw.Status(), time.Since(start).Milliseconds())
}

// Health handles GET /health.
//
// @Summary      Health check
// @Description  Returns gateway health status
// @Tags         health
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /health [get]
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// extractHeaders converts the canonical http.Header map into a flat string map
// for port-layer consumption. Only the first value per header name is used,
// matching the most common header semantics (single-value headers).
func extractHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string, len(r.Header))
	for k := range r.Header {
		headers[k] = r.Header.Get(k)
	}
	return headers
}
