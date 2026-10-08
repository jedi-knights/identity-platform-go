// login-ui is the platform's user-facing login / sign-up / consent surface
// (ADR-0011). It is the single multi-tenant origin every relying party's
// OAuth flow lands on — auth-server's /oauth/authorize redirects users
// here, and the post-authentication redemption goes back through
// /internal/issue-code to mint the authorization code.
package main

import (
	"context"
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

	inboundhttp "github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/config"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/container"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/observability"
)

// @title           Login UI
// @version         0.1
// @description     User-facing login, sign-up and consent surface for the identity platform.
// @host            localhost:8087
// @BasePath        /
func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login-ui",
		Short: "Multi-tenant login and consent surface",
		RunE:  run,
	}
}

func run(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	logger, err := observability.Setup(logging.Config{
		Level:       cfg.Log.Level,
		Format:      cfg.Log.Format,
		ServiceName: "login-ui",
		Environment: cfg.Log.Environment,
	})
	if err != nil {
		return fmt.Errorf("setting up observability: %w", err)
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer startCancel()

	shutdownTracing, err := setupTracing(startCtx, cfg, logger)
	if err != nil {
		return err
	}
	defer shutdownWithTimeout(logger, "tracing", 5*time.Second, shutdownTracing)

	ctr, err := container.New(startCtx, cfg, logger)
	if err != nil {
		return fmt.Errorf("creating container: %w", err)
	}
	defer shutdownWithTimeout(logger, "container", 30*time.Second, ctr.Close)

	router := buildRouter(startCtx, ctr, logger)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	logger.Info("starting login-ui", "addr", addr)

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
	mux := inboundhttp.NewRouter(handler, logger)
	// otelhttp wraps the router so every inbound request becomes a
	// server span; traceparent headers from the client (typically the
	// browser following the auth-server /oauth/authorize redirect) are
	// honoured by the W3C TraceContext propagator that go-platform/otel
	// registers. The wrapper is a no-op when tracing is disabled.
	return otelhttp.NewHandler(mux, "login-ui",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)
}

// setupTracing bootstraps the OTel SDK when LOGIN_UI_TRACING_ENABLED is
// set. When tracing is disabled it returns a no-op shutdown so the
// caller's deferred shutdown still has a stable target. Extracted from
// [run] so the entry point stays under the gocyclo budget.
func setupTracing(ctx context.Context, cfg *config.Config, logger logging.Logger) (platformotel.Shutdown, error) {
	if !cfg.Tracing.Enabled {
		return func(context.Context) error { return nil }, nil
	}
	shutdown, err := platformotel.Init(ctx, platformotel.Config{ //nolint:staticcheck // SA1019: tracing-only today; moving to otel.New adds a metrics listener and is a separate change
		ServiceName:      "login-ui",
		ServiceVersion:   cfg.Tracing.ServiceVersion,
		Environment:      cfg.Log.Environment,
		ExporterEndpoint: cfg.Tracing.ExporterEndpoint,
		ExporterProtocol: cfg.Tracing.ExporterProtocol,
		ExporterInsecure: cfg.Tracing.ExporterInsecure,
		SamplerRatio:     cfg.Tracing.SamplerRatio,
	})
	if err != nil {
		return nil, fmt.Errorf("setting up tracing: %w", err)
	}
	logger.Info("opentelemetry bootstrap complete", "exporter", cfg.Tracing.ExporterEndpoint)
	return shutdown, nil
}
