// Package observability bootstraps the fleet's OpenTelemetry stack
// (metrics + logs + traces) for auth-server. One Setup call returns a
// composite handle; the caller defers [otel.Observability.Shutdown].
//
// This package is the single hook for service-specific instrument
// registration — register domain counters (oauth.tokens_issued,
// oauth.token_validation, …) against the returned Meter at the
// adapter boundary once the shared observability stack is wired.
package observability

import (
	"context"
	"fmt"

	"github.com/jedi-knights/go-platform/otel"
)

// Config is the subset of [otel.Config] auth-server wires from its
// own config package. Decouples the service's config shape from the
// shared SDK's full surface — new fields on [otel.Config] do not
// require corresponding fields on the service's config type.
type Config struct {
	// ServiceName becomes the service.name resource attribute. Keep
	// this stable: dashboard queries, log pipelines, and the Fly app
	// name all join on it.
	ServiceName string

	// ServiceVersion populates service.version. Fed by the deploy
	// workflow or build tag; empty is acceptable in development.
	ServiceVersion string

	// Environment populates deployment.environment.name
	// ("production", "staging", "development").
	Environment string

	// LogLevel is "debug" | "info" | "warn" | "error". Empty
	// defaults to "info".
	LogLevel string

	// LogFormat is "json" (fleet default) | "text".
	LogFormat string

	// OTLPEndpoint is the OTLP exporter endpoint for traces (and in
	// a follow-up, logs). Empty wires the stdout exporter so spans
	// are visible during local development without a collector.
	OTLPEndpoint string

	// OTLPProtocol is "grpc" (default) | "http". Empty defers to
	// OTEL_EXPORTER_OTLP_PROTOCOL or the SDK default.
	OTLPProtocol string

	// OTLPInsecure disables TLS on the OTLP gRPC endpoint. Only
	// true for local collectors; production uses TLS.
	OTLPInsecure bool

	// SamplerRatio sets the head-based parent + ratio sampler
	// (0..1). 0 disables tracing; 1 samples every root span.
	SamplerRatio float64
}

// Setup wires the fleet OpenTelemetry stack and returns the shared
// handle. Call exactly once at the composition root; defer
// Observability.Shutdown.
func Setup(ctx context.Context, cfg Config) (*otel.Observability, error) {
	obs, err := otel.New(ctx, otel.Config{
		ServiceName:      cfg.ServiceName,
		ServiceVersion:   cfg.ServiceVersion,
		Environment:      cfg.Environment,
		ExporterEndpoint: cfg.OTLPEndpoint,
		ExporterProtocol: cfg.OTLPProtocol,
		ExporterInsecure: cfg.OTLPInsecure,
		SamplerRatio:     cfg.SamplerRatio,
		LogLevel:         cfg.LogLevel,
		LogFormat:        cfg.LogFormat,
	})
	if err != nil {
		return nil, fmt.Errorf("observability.Setup: %w", err)
	}
	return obs, nil
}
