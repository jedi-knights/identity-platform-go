package ports

// MetricsRecorder is the outbound port for recording gateway request metrics.
// Implementations should be non-blocking and must never return errors — metric
// recording failures must not affect the request path.
//
// The default implementation is a no-op. Replace it with a Prometheus or
// OpenTelemetry adapter to enable live observability.
type MetricsRecorder interface {
	// RecordRequest records a completed gateway request.
	// routeName is the matched route's Name field; statusCode is the HTTP status
	// written to the client; durationMS is the round-trip time in milliseconds.
	RecordRequest(routeName string, statusCode int, durationMS int64)
}
