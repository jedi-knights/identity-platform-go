// login-ui is the platform's user-facing login / sign-up / consent surface
// (ADR-0011). It is the single multi-tenant origin every relying party's
// OAuth flow lands on — auth-server's /oauth/authorize redirects users
// here, and the post-authentication redemption goes back through
// /internal/issue-code to mint the authorization code.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/jedi-knights/go-logging/pkg/logging"
	platform "github.com/jedi-knights/go-platform/container"
	"github.com/jedi-knights/go-platform/httpserver"

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

	startCtx, startCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer startCancel()

	obs, err := observability.Setup(startCtx, observability.Config{
		ServiceName:    "login-ui",
		ServiceVersion: cfg.Tracing.ServiceVersion,
		Environment:    cfg.Log.Environment,
		LogLevel:       cfg.Log.Level,
		LogFormat:      cfg.Log.Format,
		OTLPEndpoint:   effectiveOTLPEndpoint(cfg),
		OTLPProtocol:   cfg.Tracing.ExporterProtocol,
		OTLPInsecure:   cfg.Tracing.ExporterInsecure,
		SamplerRatio:   cfg.Tracing.SamplerRatio,
	})
	if err != nil {
		return fmt.Errorf("setting up observability: %w", err)
	}
	defer shutdownWithTimeout(obs.Logger, "observability", 10*time.Second, obs.Shutdown)

	metricsSrv, err := httpserver.StartMetricsServer("", "", obs.PromHandler)
	if err != nil {
		return fmt.Errorf("starting metrics server: %w", err)
	}
	defer shutdownWithTimeout(obs.Logger, "metrics", 5*time.Second, metricsSrv.Shutdown)
	obs.Logger.Info("metrics endpoint ready", "addr", httpserver.DefaultMetricsAddr, "path", httpserver.DefaultMetricsPath)

	ctr, err := container.New(startCtx, cfg, obs.Logger)
	if err != nil {
		return fmt.Errorf("creating container: %w", err)
	}
	defer shutdownWithTimeout(obs.Logger, "container", 30*time.Second, ctr.Close)

	router := buildRouter(startCtx, ctr, obs.Logger)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	obs.Logger.Info("starting login-ui", "addr", addr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	if err := listenAndWait(srv, quit); err != nil {
		return err
	}
	obs.Logger.Info("shutting down server")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

// effectiveOTLPEndpoint returns the configured OTLP endpoint when
// tracing is enabled; empty otherwise.
func effectiveOTLPEndpoint(cfg *config.Config) string {
	if !cfg.Tracing.Enabled {
		return ""
	}
	return cfg.Tracing.ExporterEndpoint
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
	// registers.
	return otelhttp.NewHandler(mux, "login-ui",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)
}

// listenAndWait starts the HTTP server and blocks until either it fails or
// a quit signal is received. Same shape as the other services so a reader
// only learns it once.
func listenAndWait(srv *http.Server, quit <-chan os.Signal) error {
	serverErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()
	select {
	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	case <-quit:
		return nil
	}
}
