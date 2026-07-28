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

	"github.com/jedi-knights/go-logging/pkg/logging"
	platform "github.com/jedi-knights/go-platform/container"
	platformotel "github.com/jedi-knights/go-platform/otel"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/container"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/observability"
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

	logger, err := observability.Setup(logging.Config{
		Level:       cfg.Log.Level,
		Format:      cfg.Log.Format,
		ServiceName: "entitlements-service",
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

	handler := platform.MustResolve[*inboundhttp.Handler](startCtx, ctr)
	router := otelhttp.NewHandler(
		inboundhttp.NewRouter(handler, logger),
		"entitlements-service",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logger.Info("starting entitlements-service", "addr", addr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	if err := listenAndWait(srv, quit); err != nil {
		return err
	}

	logger.Info("shutting down server")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return srv.Shutdown(ctx)
}

// setupTracing bootstraps the OTel SDK when
// ENTITLEMENTS_TRACING_ENABLED is set. Otherwise returns a no-op
// shutdown so the deferred shutdown still has a stable target.
func setupTracing(ctx context.Context, cfg *config.Config, logger logging.Logger) (platformotel.Shutdown, error) {
	if !cfg.Tracing.Enabled {
		return func(context.Context) error { return nil }, nil
	}
	shutdown, err := platformotel.Init(ctx, platformotel.Config{
		ServiceName:      "entitlements-service",
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

func shutdownWithTimeout(logger logging.Logger, name string, timeout time.Duration, fn func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := fn(ctx); err != nil {
		logger.Error(name+" shutdown error", "err", err)
	}
}

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
