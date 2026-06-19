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

	inboundhttp "github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/container"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/observability"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/ports"
)

// @title           Example Resource Service API
// @version         1.0
// @description     Protected resource API demonstrating JWT authentication and scope enforcement.
// @host            localhost:8085
// @BasePath        /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "example-resource-service",
		Short: "Example Resource Service",
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
		ServiceName: "example-resource-service",
		Environment: cfg.Log.Environment,
	})
	if err != nil {
		return fmt.Errorf("setting up observability: %w", err)
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer startCancel()

	ctr, err := container.New(startCtx, cfg, logger)
	if err != nil {
		return fmt.Errorf("creating container: %w", err)
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer closeCancel()
		if cerr := ctr.Close(closeCtx); cerr != nil {
			logger.Error("container close error", "err", cerr)
		}
	}()

	handler := platform.MustResolve[*inboundhttp.Handler](startCtx, ctr)
	introspector := platform.MustResolve[ports.TokenIntrospector](startCtx, ctr)
	router := inboundhttp.NewRouter(handler, logger, []byte(cfg.JWT.SigningKey), cfg.JWT.Audience, cfg.JWT.Issuer, introspector)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	logger.Info("starting example-resource-service", "addr", addr)

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
