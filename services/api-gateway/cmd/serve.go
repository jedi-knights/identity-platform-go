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
	"github.com/spf13/viper"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/container"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/observability"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/reload"
)

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the API gateway server",
		Long: `Start the HTTP reverse-proxy gateway.

Flag values override environment variables, which override the config file,
which overrides built-in defaults.

Security note: signing keys and TLS private keys are intentionally not
exposed as CLI flags (they would appear in process listings). Use the
corresponding GATEWAY_* environment variables or reference file paths.`,
		RunE: runServe,
	}

	// --- Server ---
	cmd.Flags().StringP("config", "c", "", "config file path (env: GATEWAY_CONFIG_FILE)")
	cmd.Flags().String("host", "0.0.0.0", "listen host (env: GATEWAY_SERVER_HOST)")
	cmd.Flags().IntP("port", "p", 8080, "listen port (env: GATEWAY_SERVER_PORT)")
	cmd.Flags().String("tls-cert", "", "TLS certificate file — requires --tls-key (env: GATEWAY_SERVER_TLS_CERT_FILE)")
	cmd.Flags().String("tls-key", "", "TLS private key file — requires --tls-cert (env: GATEWAY_SERVER_TLS_KEY_FILE)")
	cmd.Flags().Int("drain-timeout", 5, "LB drain sleep in seconds during graceful shutdown (env: GATEWAY_SERVER_DRAIN_TIMEOUT_SECS)")

	// --- Logging ---
	cmd.Flags().String("log-level", "info", "log level: debug|info|warn|error (env: GATEWAY_LOG_LEVEL)")
	cmd.Flags().String("log-format", "json", "log format: json|text (env: GATEWAY_LOG_FORMAT)")

	// --- Auth ---
	// Signing key is intentionally absent: use GATEWAY_AUTH_SIGNING_KEY env var.
	cmd.Flags().Bool("auth-enabled", false, "enable JWT authentication (env: GATEWAY_AUTH_ENABLED)")

	// --- Rate limiting ---
	cmd.Flags().Bool("rate-limit-enabled", false, "enable rate limiting (env: GATEWAY_RATE_LIMIT_ENABLED)")
	cmd.Flags().Float64("rate-limit-rps", 100, "requests per second per client (env: GATEWAY_RATE_LIMIT_REQUESTS_PER_SECOND)")
	cmd.Flags().Int("rate-limit-burst", 200, "burst size above RPS limit (env: GATEWAY_RATE_LIMIT_BURST_SIZE)")

	// --- Tracing ---
	cmd.Flags().Bool("tracing-enabled", false, "enable distributed tracing (env: GATEWAY_TRACING_ENABLED)")
	cmd.Flags().String("tracing-exporter", "stdout", "tracing exporter: stdout|otlp (env: GATEWAY_TRACING_EXPORTER)")
	cmd.Flags().String("otlp-endpoint", "", "OTLP collector host:port, e.g. otel-collector:4318 (env: GATEWAY_TRACING_OTLP_ENDPOINT)")

	return cmd
}

// bindFlags maps each cobra flag to its Viper key. Only flags that were
// explicitly set by the user (flag.Changed == true) win over env vars and the
// config file; unset flags fall through to the lower-priority sources. This is
// viper's standard BindPFlag behaviour.
func bindFlags(cmd *cobra.Command, v *viper.Viper) {
	bindings := map[string]string{
		"config":             "config_file",
		"host":               "server.host",
		"port":               "server.port",
		"tls-cert":           "server.tls_cert_file",
		"tls-key":            "server.tls_key_file",
		"drain-timeout":      "server.drain_timeout_secs",
		"log-level":          "log.level",
		"log-format":         "log.format",
		"auth-enabled":       "auth.enabled",
		"rate-limit-enabled": "rate_limit.enabled",
		"rate-limit-rps":     "rate_limit.requests_per_second",
		"rate-limit-burst":   "rate_limit.burst_size",
		"tracing-enabled":    "tracing.enabled",
		"tracing-exporter":   "tracing.exporter",
		"otlp-endpoint":      "tracing.otlp_endpoint",
	}
	for flagName, viperKey := range bindings {
		if f := cmd.Flags().Lookup(flagName); f != nil {
			_ = v.BindPFlag(viperKey, f)
		}
	}
}

// containerHandle pairs a Container with the context cancel function that stops
// its background goroutines (rate-limiter eviction loop, etc.).
type containerHandle struct {
	ctr    *container.Container
	cancel context.CancelFunc
}

// release stops the container's background goroutines and flushes OTel spans.
func (h *containerHandle) release(ctx context.Context) {
	h.cancel()
	_ = h.ctr.Shutdown(ctx)
}

func runServe(cmd *cobra.Command, _ []string) error {
	// Build a dedicated Viper instance with cobra flags bound. This ensures
	// that CLI flags take precedence over env vars and the config file while
	// leaving the hot-reload path (which calls config.Load() directly) to
	// re-read only env vars + the config file — intentional: flags are a
	// startup-time concern, not a runtime reload concern.
	v := viper.New()
	bindFlags(cmd, v)

	cfg, err := config.LoadWithViper(v)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	logger, err := observability.Setup(logging.Config{
		Level:       cfg.Log.Level,
		Format:      cfg.Log.Format,
		ServiceName: "api-gateway",
		Environment: cfg.Log.Environment,
	})
	if err != nil {
		return fmt.Errorf("setting up observability: %w", err)
	}

	// Root context cancelled when runServe returns (normal or error path).
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	ctrCtx, ctrCancel := context.WithCancel(rootCtx)
	ctr, err := container.New(ctrCtx, cfg, logger)
	if err != nil {
		ctrCancel()
		return fmt.Errorf("creating container: %w", err)
	}
	current := &containerHandle{ctr: ctr, cancel: ctrCancel}

	// AtomicHandler lets us swap the inner handler on SIGHUP without stopping
	// the HTTP server. In-flight requests on the old handler finish normally.
	atomicH := reload.New(ctr.Handler)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      atomicH,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	logger.Info("starting api-gateway", "addr", addr, "routes", len(cfg.Routes))

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)

	reloadFn := func() {
		current = hotReload(rootCtx, atomicH, current, logger)
	}

	if err := listenAndWait(srv, cfg.Server, quit, sighup, reloadFn); err != nil {
		return err
	}

	logger.Info("shutting down api-gateway")

	// Two-phase graceful shutdown:
	//   Phase 1 — Mark not-ready so /health and /ready return 503. The load
	//              balancer sees the 503 and stops routing new traffic here.
	//   Drain   — Sleep for DrainTimeoutSecs to let the LB finish draining.
	//   Phase 2 — Stop the HTTP server (drain in-flight connections).
	//   Flush   — Flush OTel spans and stop background goroutines.
	current.ctr.SetReady(false)
	if d := cfg.Server.DrainTimeoutSecs; d > 0 {
		time.Sleep(time.Duration(d) * time.Second)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	current.release(shutdownCtx)
	return nil
}

// listenAndWait starts the HTTP server in a goroutine and blocks until a
// shutdown signal arrives or the server fails. SIGHUP triggers a live config
// reload without interrupting the server.
func listenAndWait(
	srv *http.Server,
	serverCfg config.ServerConfig,
	quit <-chan os.Signal,
	sighup <-chan os.Signal,
	reloadFn func(),
) error {
	serverErr := make(chan error, 1)
	go func() {
		err := startServer(srv, serverCfg)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()
	for {
		select {
		case err := <-serverErr:
			return fmt.Errorf("server error: %w", err)
		case <-sighup:
			reloadFn()
		case <-quit:
			return nil
		}
	}
}

// startServer calls ListenAndServeTLS when TLS cert and key are both configured,
// otherwise it calls ListenAndServe.
func startServer(srv *http.Server, cfg config.ServerConfig) error {
	if cfg.TLSCertFile != "" {
		return srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	return srv.ListenAndServe()
}

// hotReload loads a fresh config from file+env (no CLI flags — those are a
// startup concern), builds a new container, atomically swaps the handler, then
// releases the old container after a brief grace period.
func hotReload(
	rootCtx context.Context,
	atomicH *reload.AtomicHandler,
	old *containerHandle,
	logger logging.Logger,
) *containerHandle {
	newCfg, err := config.Load()
	if err != nil {
		logger.Error("hot reload: config load failed", "error", err)
		return old
	}

	newCtx, newCancel := context.WithCancel(rootCtx)
	newCtr, err := container.New(newCtx, newCfg, logger)
	if err != nil {
		newCancel()
		logger.Error("hot reload: container build failed", "error", err)
		return old
	}

	atomicH.Swap(newCtr.Handler)
	logger.Info("hot reload successful")

	// Release the old container after a brief grace period to let any request
	// dispatched to the old handler just before the swap finish cleanly.
	go func() {
		time.Sleep(5 * time.Second)
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer releaseCancel()
		old.release(releaseCtx)
	}()

	return &containerHandle{ctr: newCtr, cancel: newCancel}
}
