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

	inboundhttp "github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/container"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/observability"
)

// @title           Client Registry Service API
// @version         1.0
// @description     OAuth2 client registration, management, and credential validation.
// @host            localhost:8082
// @BasePath        /
func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "client-registry-service",
		Short: "OAuth2 Client Registry Service",
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
		ServiceName:    "client-registry-service",
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
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	obs.Logger.Info("starting client-registry-service", "addr", addr)

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
// error against the supplied name.
func shutdownWithTimeout(logger logging.Logger, name string, timeout time.Duration, fn func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := fn(ctx); err != nil {
		logger.Error(name+" shutdown error", "err", err)
	}
}

// buildRouter resolves the handler graph from the container, wires the
// HTTP routes, and wraps the result with otelhttp so every request
// becomes a server span.
func buildRouter(ctx context.Context, ctr *platform.Container, logger logging.Logger) http.Handler {
	handler := platform.MustResolve[*inboundhttp.Handler](ctx, ctr)
	// RegistrationHandler and RegistrationManagementHandler are
	// nil-resolved when DCR is disabled (no CLIENT_REGISTRATION_BASE_URL);
	// the router skips /register and the RFC 7592 management routes.
	registration := platform.MustResolve[*inboundhttp.RegistrationHandler](ctx, ctr)
	management := platform.MustResolve[*inboundhttp.RegistrationManagementHandler](ctx, ctr)
	mux := inboundhttp.NewRouter(handler, registration, management, logger)
	return otelhttp.NewHandler(mux, "client-registry-service",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)
}

// listenAndWait starts the HTTP server and blocks until either it fails or a quit signal is received.
// serverErr is buffered (cap 1) so the server goroutine can always complete its send and exit
// without blocking, even after a quit signal wins the select. A startup failure that races
// with the quit signal is intentionally dropped here — the caller is already handling shutdown.
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
