package http

import (
	"net/http"

	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// Handler implements the gateway's HTTP endpoints.
type Handler struct {
	resolver  ports.RouteResolver
	proxyMap  *ProxyMap
	healthAgg ports.HealthAggregator
	logger    logging.Logger
}

// NewHandler creates a new gateway handler.
func NewHandler(
	resolver ports.RouteResolver,
	proxyMap *ProxyMap,
	healthAgg ports.HealthAggregator,
	logger logging.Logger,
) *Handler {
	return &Handler{
		resolver:  resolver,
		proxyMap:  proxyMap,
		healthAgg: healthAgg,
		logger:    logger,
	}
}

// Health returns the aggregate health status of all downstream services.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	report := h.healthAgg.AggregateHealth(r.Context())
	status := http.StatusOK
	if report.Status == "unhealthy" {
		status = http.StatusServiceUnavailable
	}
	httputil.WriteJSON(w, status, report)
}

// Proxy resolves the request path to a backend route and forwards the request
// using the pre-built reverse proxy for that route. Returns 502 Bad Gateway
// if no route matches the request path.
func (h *Handler) Proxy(w http.ResponseWriter, r *http.Request) {
	route, ok := h.resolver.Resolve(r.URL.Path)
	if !ok {
		h.logger.Warn("no route matched", "path", r.URL.Path)
		http.Error(w, "no upstream configured for this path", http.StatusBadGateway)
		return
	}

	proxy, ok := h.proxyMap.Get(route.PathPrefix)
	if !ok {
		h.logger.Error("proxy not found for resolved route", "prefix", route.PathPrefix)
		http.Error(w, "internal routing error", http.StatusInternalServerError)
		return
	}

	h.logger.Debug("proxying request", "path", r.URL.Path, "backend", route.BackendURL)
	proxy.ServeHTTP(w, r)
}
