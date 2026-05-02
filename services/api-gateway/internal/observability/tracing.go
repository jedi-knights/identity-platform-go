package observability

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
)

// SetupTracing initialises the OpenTelemetry trace provider from cfg.
//
// When cfg.Enabled is false a no-op provider is returned; no spans are created
// or exported and the function succeeds without allocating SDK resources.
//
// When cfg.Enabled is true the function:
//  1. Creates the requested span exporter (currently "stdout"; extend for OTLP).
//  2. Builds a BatchSpanProcessor-backed TracerProvider annotated with the
//     service name from cfg.ServiceName.
//  3. Installs a global W3C TraceContext + Baggage propagator so that
//     traceparent/tracestate headers are automatically extracted from inbound
//     requests and injected into outbound requests made via otelhttp.
//
// The returned shutdown function must be called on process exit (after draining
// in-flight spans). Pass it the shutdown context from the graceful-shutdown path.
func SetupTracing(cfg config.TracingConfig) (trace.TracerProvider, func(context.Context) error, error) {
	if !cfg.Enabled {
		return noop.NewTracerProvider(), noopShutdown, nil
	}

	exp, err := buildExporter(cfg)
	if err != nil {
		return nil, nil, err
	}

	res := sdkresource.NewWithAttributes(
		// Schema URL is the semantic conventions version the attributes follow.
		// We pin to the version we compiled against; bump when semconv version bumps.
		"https://opentelemetry.io/schemas/1.26.0",
		attribute.String("service.name", cfg.ServiceName),
	)

	tp := sdktrace.NewTracerProvider(
		// BatchSpanProcessor buffers spans and exports them asynchronously.
		// This is preferred over the synchronous processor in production as it
		// decouples span export latency from request latency.
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)

	// The global propagator is used by otelhttp and any other OTel-instrumented
	// HTTP clients to extract/inject W3C Trace Context headers automatically.
	// TraceContext propagates traceparent and tracestate (distributed trace IDs).
	// Baggage propagates key-value pairs across service boundaries.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp, tp.Shutdown, nil
}

// buildExporter creates the span exporter described by cfg.
//
// Supported exporters:
//   - "stdout" or "" — pretty-prints spans as JSON to stdout (development).
//   - "otlp"         — sends spans to an OTLP/HTTP collector. cfg.OTLPEndpoint
//     sets the collector host:port (e.g. "otel-collector:4318").
//     The env var OTEL_EXPORTER_OTLP_ENDPOINT overrides it at runtime.
func buildExporter(cfg config.TracingConfig) (sdktrace.SpanExporter, error) {
	switch cfg.Exporter {
	case "stdout", "":
		// WithPrettyPrint formats each span as indented JSON — useful for local
		// development when reading spans in the terminal.
		return stdouttrace.New(stdouttrace.WithPrettyPrint())
	case "otlp":
		opts := []otlptracehttp.Option{}
		if cfg.OTLPEndpoint != "" {
			opts = append(opts, otlptracehttp.WithEndpoint(cfg.OTLPEndpoint))
		}
		return otlptracehttp.New(context.Background(), opts...)
	default:
		return nil, fmt.Errorf("unknown tracing exporter %q; supported: stdout, otlp", cfg.Exporter)
	}
}

// noopShutdown is a no-op shutdown function returned when tracing is disabled.
func noopShutdown(_ context.Context) error { return nil }
