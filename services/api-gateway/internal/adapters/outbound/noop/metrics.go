package noop

import "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"

// MetricsRecorder is a no-op implementation of ports.MetricsRecorder.
// It is the default metrics adapter — safe to use without any observability
// infrastructure. Replace it with a Prometheus or OpenTelemetry adapter
// in production deployments that require live metrics.
type MetricsRecorder struct{}

// Compile-time check: MetricsRecorder must satisfy ports.MetricsRecorder.
var _ ports.MetricsRecorder = (*MetricsRecorder)(nil)

// NewMetricsRecorder returns a MetricsRecorder that discards all observations.
func NewMetricsRecorder() *MetricsRecorder {
	return &MetricsRecorder{}
}

// RecordRequest discards the observation. It never panics and always returns immediately.
func (*MetricsRecorder) RecordRequest(_ string, _ int, _ int64) {}
