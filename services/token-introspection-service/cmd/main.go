package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jedi-knights/go-logging/pkg/logging"
	platform "github.com/jedi-knights/go-platform/container"
	"github.com/jedi-knights/go-platform/httpserver"
	platformotel "github.com/jedi-knights/go-platform/otel"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/container"
)

// @title           Token Introspection Service API
// @version         1.0
// @description     JWT token validation and metadata extraction per RFC 7662.
// @host            localhost:8083
// @BasePath        /
func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "token-introspection-service",
		Short: "Token Introspection Service",
		RunE:  run,
	}
}

func run(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	startupCtx, startupCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer startupCancel()

	obs, shutdownObs, err := setupObservability(startupCtx, cfg)
	if err != nil {
		return err
	}
	logger := obs.Logger
	defer shutdownWithTimeout(logger, "observability", 5*time.Second, shutdownObs)

	ctr, err := container.New(startupCtx, cfg, logger)
	if err != nil {
		return fmt.Errorf("creating container: %w", err)
	}
	defer shutdownWithTimeout(logger, "container", 30*time.Second, ctr.Close)

	handler := platform.MustResolve[*inboundhttp.Handler](startupCtx, ctr)
	// otelhttp wraps the router so every inbound request becomes a
	// server span; traceparent headers from the client are honoured by
	// the W3C TraceContext propagator that go-platform/otel registers.
	// The wrapper is a no-op when tracing is disabled.
	router := otelhttp.NewHandler(inboundhttp.NewRouter(handler, logger), "token-introspection-service",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	logger.Info("starting token-introspection-service", "addr", addr)

	// Run serves until SIGINT/SIGTERM, then drains in-flight requests within the
	// standard shutdown budget.
	if err := httpserver.New(addr, router).Run(context.Background()); err != nil {
		return err
	}
	logger.Info("server stopped")
	return nil
}

// setupObservability wires traces, metrics, and logs through otel.New and
// starts the Prometheus scrape listener (INTROSPECT_METRICS_ADDR, default :9464).
// Trace export is controlled by INTROSPECT_TRACING_ENABLED: when off the tracer never
// samples, but metrics and the span-aware logger still run. The returned
// shutdown stops the listener and flushes the providers.
func setupObservability(ctx context.Context, cfg *config.Config) (*platformotel.Observability, func(context.Context) error, error) {
	sampler := cfg.Tracing.SamplerRatio
	if !cfg.Tracing.Enabled {
		sampler = -1 // negative ratio is a parent-based never-sample; see otel.Config.SamplerRatio
	}
	obs, err := platformotel.New(ctx, platformotel.Config{
		ServiceName:      "token-introspection-service",
		ServiceVersion:   cfg.Tracing.ServiceVersion,
		Environment:      cfg.Log.Environment,
		ExporterEndpoint: cfg.Tracing.ExporterEndpoint,
		ExporterProtocol: cfg.Tracing.ExporterProtocol,
		ExporterInsecure: cfg.Tracing.ExporterInsecure,
		SamplerRatio:     sampler,
		LogLevel:         cfg.Log.Level,
		LogFormat:        cfg.Log.Format,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("setting up observability: %w", err)
	}

	metricsSrv, err := httpserver.StartMetricsServer(cfg.Metrics.Addr, "", obs.PromHandler)
	if err != nil {
		_ = obs.Shutdown(ctx) // best-effort cleanup; the listen error is the actionable one
		return nil, nil, fmt.Errorf("starting metrics server: %w", err)
	}
	obs.Logger.Info("observability ready",
		"tracing_enabled", cfg.Tracing.Enabled, "metrics_addr", metricsSrv.Server.Addr)

	shutdown := func(sctx context.Context) error {
		return errors.Join(metricsSrv.Shutdown(sctx), obs.Shutdown(sctx))
	}
	return obs, shutdown, nil
}

// shutdownWithTimeout runs fn with its own bounded context and logs any
// error against the supplied name.
func shutdownWithTimeout(logger logging.Logger, name string, timeout time.Duration, fn func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := fn(ctx); err != nil {
		logger.Error(name+" shutdown error", "err", err)
	}
}
