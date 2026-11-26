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

	inboundhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/config"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/container"
)

// @title           Auth Server API
// @version         1.0
// @description     OAuth2 Authorization Server - token issuance, introspection, and revocation.
// @host            localhost:8080
// @BasePath        /
func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "auth-server",
		Short: "OAuth2 Authorization Server",
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

	router := buildRouter(startCtx, ctr, logger)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	logger.Info("starting auth-server", "addr", addr)

	// Run serves until SIGINT/SIGTERM, then drains in-flight requests within the
	// standard shutdown budget.
	if err := httpserver.New(addr, router).Run(context.Background()); err != nil {
		return err
	}
	logger.Info("server stopped")
	return nil
}

// shutdownWithTimeout runs fn with its own bounded context and logs any
// error against the supplied name. Inlined as a defer in [run] it
// pushed the entry point over the gocyclo budget; a named helper lifts
// each deferred branch out of [run]'s tally.
func shutdownWithTimeout(logger logging.Logger, name string, timeout time.Duration, fn func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := fn(ctx); err != nil {
		logger.Error(name+" shutdown error", "err", err)
	}
}

// buildRouter resolves the handler graph from the container, wires the
// HTTP routes, and wraps the result with otelhttp so every request
// becomes a server span. Extracted from [run] so the entry point stays
// under the gocyclo budget.
func buildRouter(ctx context.Context, ctr *platform.Container, logger logging.Logger) http.Handler {
	handler := platform.MustResolve[*inboundhttp.Handler](ctx, ctr)
	// JWKSHandler is nil-resolved in HS256 mode; NewRouter skips the
	// route in that case.
	jwks := platform.MustResolve[*inboundhttp.JWKSHandler](ctx, ctr)
	// UserInfoHandler is nil-resolved when OIDC mode is disabled.
	userInfo := platform.MustResolve[*inboundhttp.UserInfoHandler](ctx, ctr)
	// MetadataHandler is nil-resolved when AUTH_METADATA_PUBLIC_BASE_URL
	// is unset (ADR-0012).
	metadata := platform.MustResolve[*inboundhttp.MetadataHandler](ctx, ctr)
	// DeviceAuthorizationHandler is nil-resolved when AUTH_LOGIN_UI_URL is
	// unset (ADR-0022).
	deviceAuth := platform.MustResolve[*inboundhttp.DeviceAuthorizationHandler](ctx, ctr)
	mux := inboundhttp.NewRouter(handler, jwks, userInfo, metadata, deviceAuth, logger)
	// otelhttp wraps the router so every inbound request becomes a
	// server span; traceparent headers from the client are honoured by
	// the W3C TraceContext propagator that go-platform/otel registers.
	// The wrapper is a no-op when tracing is disabled.
	return otelhttp.NewHandler(mux, "auth-server",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)
}

// setupObservability wires traces, metrics, and logs through otel.New and
// starts the Prometheus scrape listener (AUTH_METRICS_ADDR, default :9464).
// Trace export is controlled by AUTH_TRACING_ENABLED: when off the tracer never
// samples, but metrics and the span-aware logger still run. The returned
// shutdown stops the listener and flushes the providers.
func setupObservability(ctx context.Context, cfg *config.Config) (*platformotel.Observability, func(context.Context) error, error) {
	sampler := cfg.Tracing.SamplerRatio
	if !cfg.Tracing.Enabled {
		sampler = -1 // negative ratio is a parent-based never-sample; see otel.Config.SamplerRatio
	}
	obs, err := platformotel.New(ctx, platformotel.Config{
		ServiceName:      "auth-server",
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
