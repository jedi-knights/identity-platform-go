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

	"github.com/jedi-knights/go-logging/pkg/logging"
	platform "github.com/jedi-knights/go-platform/container"

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
	router := inboundhttp.NewRouter(handler, logger)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	logger.Info("starting login-ui", "addr", addr)

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
