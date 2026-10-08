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

	inboundhttp "github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/container"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/observability"
)

// @title           Authorization Policy Service API
// @version         1.0
// @description     RBAC policy evaluator over {subject, resource, action} tuples.
// @host            localhost:8084
// @BasePath        /
func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "authorization-policy-service",
		Short: "RBAC Authorization Policy Service",
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
		ServiceName:    "authorization-policy-service",
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

	handler := platform.MustResolve[*inboundhttp.Handler](startCtx, ctr)
	// otelhttp wraps the router so every inbound request becomes a
	// server span; traceparent headers from the client are honoured by
	// the W3C TraceContext propagator that go-platform/otel registers.
	router := otelhttp.NewHandler(inboundhttp.NewRouter(handler, obs.Logger), "authorization-policy-service",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	obs.Logger.Info("starting authorization-policy-service", "addr", addr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	if err := listenAndWait(srv, quit); err != nil {
		return err
	}

	obs.Logger.Info("shutting down server")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutCancel()

	return srv.Shutdown(shutCtx)
}

// effectiveOTLPEndpoint returns the configured OTLP endpoint when
// tracing is enabled; empty otherwise. The empty value makes the
// shared observability bootstrap wire the stdout exporter — useful
// for local development without a collector.
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

// listenAndWait starts the HTTP server and blocks until either it fails or a quit signal is received.
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
