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

	inboundhttp "github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/container"
)

// @title       Entitlements Service API
// @version     1.0
// @description Account, seat, and entitlement catalog service.
// @host        localhost:8086
// @BasePath    /
func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "entitlements-service",
		Short: "Account, seat, and entitlement catalog service",
		RunE:  run,
	}
}

func run(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer startCancel()

	obs, shutdownObs, err := setupObservability(startCtx, cfg)
	if err != nil {
		return err
	}
	logger := obs.Logger
	defer shutdownWithTimeout(logger, "observability", 5*time.Second, shutdownObs)

	ctr, err := container.New(startCtx, cfg, logger)
	if err != nil {
		return fmt.Errorf("creating container: %w", err)
	}
	defer shutdownWithTimeout(logger, "container", 30*time.Second, ctr.Close)

	handler := platform.MustResolve[*inboundhttp.Handler](startCtx, ctr)
	router := otelhttp.NewHandler(
		inboundhttp.NewRouter(handler, logger),
		"entitlements-service",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	logger.Info("starting entitlements-service", "addr", addr)

	// Run serves until SIGINT/SIGTERM, then drains in-flight requests within
	// the standard shutdown budget.
	if err := httpserver.New(addr, router).Run(context.Background()); err != nil {
		return err
	}
	logger.Info("server stopped")
	return nil
}

// setupObservability wires traces, metrics, and logs through otel.New and
// starts the Prometheus scrape listener (ENTITLEMENTS_METRICS_ADDR, default :9464).
// Trace export is controlled by ENTITLEMENTS_TRACING_ENABLED: when off the tracer never
// samples, but metrics and the span-aware logger still run. The returned
// shutdown stops the listener and flushes the providers.
func setupObservability(ctx context.Context, cfg *config.Config) (*platformotel.Observability, func(context.Context) error, error) {
	sampler := cfg.Tracing.SamplerRatio
	if !cfg.Tracing.Enabled {
		sampler = -1 // negative ratio is a parent-based never-sample; see otel.Config.SamplerRatio
	}
	obs, err := platformotel.New(ctx, platformotel.Config{
		ServiceName:      "entitlements-service",
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

func shutdownWithTimeout(logger logging.Logger, name string, timeout time.Duration, fn func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := fn(ctx); err != nil {
		logger.Error(name+" shutdown error", "err", err)
	}
}
