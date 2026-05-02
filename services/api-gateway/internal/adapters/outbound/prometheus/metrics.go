// Package prometheus is the outbound adapter that records gateway metrics using
// the Prometheus instrumentation library.
//
// Design: Strategy pattern — implements ports.MetricsRecorder so the container
// can swap this in place of the no-op adapter without touching application logic.
//
// Each MetricsRecorder owns its own Prometheus registry (rather than using the
// global DefaultRegisterer) so that multiple instances can coexist in tests
// without "already registered" panics.
package prometheus

import (
	"net/http"
	"strconv"

	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// Compile-time guard: MetricsRecorder must satisfy the port interface.
var _ ports.MetricsRecorder = (*MetricsRecorder)(nil)

// MetricsRecorder records gateway request metrics using Prometheus counters
// and histograms. Obtain one via NewMetricsRecorder and register its HTTP
// handler at /metrics in the router.
type MetricsRecorder struct {
	registry      *prom.Registry
	requestsTotal *prom.CounterVec
	durationMS    *prom.HistogramVec
}

// NewMetricsRecorder creates a MetricsRecorder with an isolated Prometheus
// registry pre-populated with Go runtime and process collectors in addition
// to the two gateway-specific metrics.
func NewMetricsRecorder() *MetricsRecorder {
	reg := prom.NewRegistry()

	// Standard Go runtime metrics: heap, GC pauses, goroutine count, etc.
	// Using the collectors sub-package (the top-level helpers are deprecated in v1.13+).
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	// gateway_requests_total — counter partitioned by route name and HTTP status.
	// Use this to compute error rates: sum(rate(gateway_requests_total{status=~"5.."}[5m]))
	requestsTotal := prom.NewCounterVec(
		prom.CounterOpts{
			Name: "gateway_requests_total",
			Help: "Total gateway requests partitioned by route name and HTTP status code.",
		},
		[]string{"route", "status"},
	)

	// gateway_request_duration_ms — latency histogram per route.
	// Buckets are tuned for typical inter-service latency (sub-ms to several seconds).
	durationMS := prom.NewHistogramVec(
		prom.HistogramOpts{
			Name:    "gateway_request_duration_ms",
			Help:    "Gateway request round-trip duration in milliseconds.",
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000},
		},
		[]string{"route"},
	)

	reg.MustRegister(requestsTotal, durationMS)

	return &MetricsRecorder{
		registry:      reg,
		requestsTotal: requestsTotal,
		durationMS:    durationMS,
	}
}

// Handler returns an http.Handler that serves the Prometheus text exposition
// format for this recorder's registry. Register it at GET /metrics.
func (m *MetricsRecorder) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// RecordRequest increments the requests counter and records the latency
// observation. It never blocks and never returns an error; metric failures
// must not affect the request path (contract from ports.MetricsRecorder).
func (m *MetricsRecorder) RecordRequest(routeName string, statusCode int, durationMS int64) {
	m.requestsTotal.WithLabelValues(routeName, strconv.Itoa(statusCode)).Inc()
	m.durationMS.WithLabelValues(routeName).Observe(float64(durationMS))
}
