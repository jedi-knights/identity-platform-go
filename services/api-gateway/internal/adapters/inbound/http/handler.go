package http

import (
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/application"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// headerPool reuses map[string]string allocations across Proxy calls.
// Maps are pre-allocated with capacity 16 (covers most request header counts).
// Each map is cleared before returning to the pool so stale entries cannot leak
// across requests.
var headerPool = sync.Pool{
	New: func() any { return make(map[string]string, 16) },
}

// Handler holds all inbound HTTP handler dependencies.
// It is intentionally thin: each method extracts the minimum set of attributes
// from the *http.Request, delegates decisions to ports, and writes the response.
//
// Design: each field is a port interface (Strategy pattern), so the concrete
// adapter wired in by the container can be swapped without changing this type.
//
// ready gates the /health endpoint for two-phase graceful shutdown:
//   - true  (default) — normal operation, health check runs against upstreams
//   - false           — gateway is draining; /health returns 503 immediately so
//     the load balancer stops routing new traffic before server.Shutdown is called
type Handler struct {
	router    ports.RequestRouter
	transport ports.UpstreamTransport
	metrics   ports.MetricsRecorder
	logger    logging.Logger
	// health is optional; when nil, Health returns a simple {"status":"ok"} response.
	// When wired, it calls the HealthAggregator which fans out to all upstreams.
	health ports.HealthAggregator
	ready  atomic.Bool
}

// NewHandler creates a Handler with the provided port implementations.
// Pass nil for health to use the simple static health response.
// The handler starts in the ready state (ready=true); call SetReady(false) to
// begin the two-phase graceful shutdown sequence.
func NewHandler(
	router ports.RequestRouter,
	transport ports.UpstreamTransport,
	metrics ports.MetricsRecorder,
	logger logging.Logger,
	health ports.HealthAggregator,
) *Handler {
	h := &Handler{
		router:    router,
		transport: transport,
		metrics:   metrics,
		logger:    logger,
		health:    health,
	}
	h.ready.Store(true)
	return h
}

// SetReady sets the gateway readiness state. Passing false causes Health to
// return 503 immediately, signalling the load balancer to stop routing new
// traffic without terminating in-flight connections.
func (h *Handler) SetReady(v bool) { h.ready.Store(v) }

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
	headers := acquireHeaders(r)
	route, err := h.router.Route(r.Context(), r.Method, r.URL.Path, headers)
	releaseHeaders(headers) // Route() does not retain the map; release before the upstream round-trip
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
		status := http.StatusInternalServerError
		if rw.Written() {
			status = rw.Status()
		} else {
			httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "upstream error"))
		}
		h.metrics.RecordRequest(route.Name, status, time.Since(start).Milliseconds())
		return
	}

	h.metrics.RecordRequest(route.Name, rw.Status(), time.Since(start).Milliseconds())
}

// Health handles GET /health.
//
// When a HealthAggregator is wired, it fans out concurrently to all upstream
// /health endpoints and returns an aggregate report. Without one it returns a
// simple static response — useful during startup or in tests.
//
// HTTP status:
//   - 200 OK        — gateway is healthy or degraded (still serving)
//   - 503 Unavailable — all upstreams are down
//
// @Summary      Health check
// @Description  Returns gateway and upstream health status
// @Tags         health
// @Produce      json
// @Success      200  {object}  ports.HealthReport
// @Failure      503  {object}  ports.HealthReport
// @Router       /health [get]
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	// Phase 1 of two-phase graceful shutdown: return 503 immediately when not
	// ready so the load balancer drains this instance before server.Shutdown runs.
	if !h.ready.Load() {
		httputil.WriteJSON(w, http.StatusServiceUnavailable,
			map[string]string{"status": "shutting_down"})
		return
	}

	// When no aggregator is wired (e.g. in tests or minimal deployments),
	// fall back to a simple static response.
	if h.health == nil {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	report := h.health.AggregateHealth(r.Context())

	// Return 503 only when every upstream is down; a partially-degraded gateway
	// can still serve some traffic, so "degraded" stays at 200.
	statusCode := http.StatusOK
	if report.Status == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	}

	httputil.WriteJSON(w, statusCode, report)
}

// Ready handles GET /ready.
//
// Unlike /health, which consults upstream services, /ready answers purely from
// the gateway's local state. It is the correct endpoint to register with a load
// balancer readiness probe: returning 503 here tells the LB to stop routing new
// traffic, which is Phase 1 of the two-phase graceful shutdown.
//
// @Summary      Readiness probe
// @Description  Returns 200 when the gateway is ready to serve, 503 when draining
// @Tags         health
// @Produce      json
// @Success      200  {object}  map[string]string
// @Failure      503  {object}  map[string]string
// @Router       /ready [get]
func (h *Handler) Ready(w http.ResponseWriter, _ *http.Request) {
	if !h.ready.Load() {
		httputil.WriteJSON(w, http.StatusServiceUnavailable,
			map[string]string{"status": "not_ready"})
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// acquireHeaders gets a map from the pool and populates it from r's headers.
// Only the first value per header name is used (single-value header semantics).
// The caller must call releaseHeaders when done so the map is returned to the pool.
func acquireHeaders(r *http.Request) map[string]string {
	m := headerPool.Get().(map[string]string)
	for k, vs := range r.Header {
		if len(vs) > 0 {
			m[k] = vs[0]
		}
	}
	return m
}

// releaseHeaders clears m and returns it to the pool.
func releaseHeaders(m map[string]string) {
	clear(m)
	headerPool.Put(m)
}
