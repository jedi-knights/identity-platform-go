//go:build unit

package observability_test

import (
	"context"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/observability"
)

// TestSetupTracing_Disabled verifies that when tracing is disabled, SetupTracing
// returns a no-op provider, a no-op shutdown, and no error — without allocating
// any SDK resources.
func TestSetupTracing_Disabled(t *testing.T) {
	cfg := config.TracingConfig{Enabled: false}

	tp, shutdown, err := observability.SetupTracing(cfg)
	if err != nil {
		t.Fatalf("SetupTracing(disabled) error: %v", err)
	}
	if tp == nil {
		t.Fatal("expected non-nil TracerProvider")
	}
	if shutdown == nil {
		t.Fatal("expected non-nil shutdown function")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("no-op shutdown returned error: %v", err)
	}
}

// TestSetupTracing_StdoutExporter verifies that the "stdout" exporter initialises
// without error and returns a functional TracerProvider and shutdown function.
func TestSetupTracing_StdoutExporter(t *testing.T) {
	cfg := config.TracingConfig{
		Enabled:     true,
		ServiceName: "api-gateway-test",
		Exporter:    "stdout",
	}

	tp, shutdown, err := observability.SetupTracing(cfg)
	if err != nil {
		t.Fatalf("SetupTracing(stdout) error: %v", err)
	}
	if tp == nil {
		t.Fatal("expected non-nil TracerProvider")
	}
	if shutdown == nil {
		t.Fatal("expected non-nil shutdown function")
	}

	// The shutdown must flush and release resources without error.
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown returned error: %v", err)
	}
}

// TestSetupTracing_UnknownExporter verifies that an unsupported exporter name
// returns a descriptive error rather than silently falling back.
func TestSetupTracing_UnknownExporter(t *testing.T) {
	cfg := config.TracingConfig{
		Enabled:     true,
		ServiceName: "api-gateway-test",
		Exporter:    "zipkin",
	}

	_, _, err := observability.SetupTracing(cfg)
	if err == nil {
		t.Fatal("expected error for unknown exporter, got nil")
	}
}

// TestSetupTracing_OTLPExporter verifies that the "otlp" exporter initialises
// without error when a (non-existent) endpoint is configured. The OTLP exporter
// is lazy — it does not connect until spans are exported, so the test just
// checks that the TracerProvider and shutdown function are returned correctly.
func TestSetupTracing_OTLPExporter(t *testing.T) {
	cfg := config.TracingConfig{
		Enabled:      true,
		ServiceName:  "api-gateway-test",
		Exporter:     "otlp",
		OTLPEndpoint: "localhost:4318", // no real collector; connection is lazy
	}

	tp, shutdown, err := observability.SetupTracing(cfg)
	if err != nil {
		t.Fatalf("SetupTracing(otlp) error: %v", err)
	}
	if tp == nil {
		t.Fatal("expected non-nil TracerProvider")
	}
	if shutdown == nil {
		t.Fatal("expected non-nil shutdown function")
	}
	// Shutdown with a very short deadline; we expect a connection error since no
	// collector is running, but that is acceptable — what we're testing is that
	// the exporter was created and the SDK is correctly initialized.
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	_ = shutdown(ctx) // error is expected and intentionally ignored
}

// TestSetupTracing_OTLPExporter_NoEndpoint verifies that the "otlp" exporter
// initialises correctly even when OTLPEndpoint is empty — the SDK will use the
// OTEL_EXPORTER_OTLP_ENDPOINT env var or the default (localhost:4318).
func TestSetupTracing_OTLPExporter_NoEndpoint(t *testing.T) {
	cfg := config.TracingConfig{
		Enabled:      true,
		ServiceName:  "api-gateway-test",
		Exporter:     "otlp",
		OTLPEndpoint: "",
	}

	tp, shutdown, err := observability.SetupTracing(cfg)
	if err != nil {
		t.Fatalf("SetupTracing(otlp, no endpoint) error: %v", err)
	}
	if tp == nil {
		t.Fatal("expected non-nil TracerProvider")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	_ = shutdown(ctx)
}

// TestSetupTracing_EmptyExporterDefaultsToStdout verifies that an empty exporter
// string falls back to the stdout exporter (the case when users omit the field).
func TestSetupTracing_EmptyExporterDefaultsToStdout(t *testing.T) {
	cfg := config.TracingConfig{
		Enabled:     true,
		ServiceName: "api-gateway-test",
		Exporter:    "",
	}

	tp, shutdown, err := observability.SetupTracing(cfg)
	if err != nil {
		t.Fatalf("SetupTracing(empty exporter) error: %v", err)
	}
	if tp == nil {
		t.Fatal("expected non-nil TracerProvider")
	}
	_ = shutdown(context.Background())
}
