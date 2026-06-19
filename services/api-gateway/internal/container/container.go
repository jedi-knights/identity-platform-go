// Package container is the dependency injection root for the api-gateway.
//
// Design: every concrete adapter is constructed and wired inside the eager
// providers registered on a [platform.Container]. Resolution from the
// returned container is restricted to the composition root in cmd/serve.go
// and tests; business code receives its dependencies via constructor
// parameters.
package container

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"
	platform "github.com/jedi-knights/go-platform/container"

	hs256auth "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/inbound/auth/hs256"
	jwksauth "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/inbound/auth/jwks"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/anthropic"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/circuitbreaker"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/fixedwindow"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/healthhttp"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/leakybucket"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/memory"
	prometheusout "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/prometheus"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/proxy"
	retryout "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/retry"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/roundrobin"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/slidingwindowcounter"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/slidingwindowlog"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/static"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/weighted"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/application"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/observability"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// New constructs and bootstraps a platform container wired with every
// dependency the api-gateway needs.
//
// ctx controls the lifecycle of background goroutines started by adapters
// (e.g. the rate-limiter eviction loop). Cancel it on shutdown to release
// those resources; the platform container's [platform.Container.Close]
// additionally flushes the OTel trace provider via an OnClose hook
// registered by the router provider.
//
// Adapter selection (preserved verbatim from the prior implementation):
//
//   - RouteResolver:     static.Resolver — loads routes from config at startup
//   - UpstreamTransport: proxy.Transport wrapped by URL picker, optionally by
//     retry and circuit breaker (Decorator pattern)
//   - MetricsRecorder:   prometheusout.MetricsRecorder
//   - HealthChecker:     healthhttp.Checker
//   - RateLimiter:       strategy selected by cfg.RateLimit.Strategy; nil when disabled
//   - MCPDecider:        Anthropic Claude adapter when GATEWAY_MCP_ANTHROPIC_API_KEY is set;
//     static fallback otherwise
//   - MCPRateLimiter:    in-memory adapter (replace with Redis adapter for
//     multi-instance deployments)
//
// Two values exposed via Resolve at the composition root:
//
//   - *inboundhttp.Handler — so cmd/serve.go can call handler.SetReady(false)
//     during graceful shutdown
//   - http.Handler — the assembled router that the HTTP server consumes
func New(ctx context.Context, cfg *config.Config, logger logging.Logger) (*platform.Container, error) {
	if cfg == nil {
		return nil, apperrors.New(apperrors.ErrCodeInternal, "config is required")
	}
	if logger == nil {
		return nil, apperrors.New(apperrors.ErrCodeInternal, "logger is required")
	}

	c := platform.New()

	platform.Register(c, func(_ context.Context, _ *platform.Container) (*config.Config, error) {
		return cfg, nil
	})
	platform.Register(c, func(_ context.Context, _ *platform.Container) (logging.Logger, error) {
		return logger, nil
	})
	platform.Register(c, func(_ context.Context, _ *platform.Container) (lifecycleCtx, error) {
		return lifecycleCtx{ctx: ctx}, nil
	})

	// Shared building blocks resolved by downstream providers.
	platform.Register(c, httpClientProvider)
	platform.Register(c, routesProvider)
	platform.Register(c, transportProvider)
	platform.Register(c, metricsRecorderProvider)
	platform.Register(c, gatewayServiceProvider)
	platform.Register(c, healthAggregatorProvider)
	platform.Register(c, handlerProvider)
	platform.Register(c, mcpHandlerProvider)

	// The router pulls every concern together and registers the OTel tracer
	// shutdown as an OnClose hook on the container.
	platform.Register(c, routerProvider)

	if err := c.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrapping container: %w", err)
	}
	return c, nil
}

// lifecycleCtx wraps the caller-supplied context so providers that need to
// start background goroutines can resolve it explicitly. The wrapper type
// avoids registering raw context.Context, which would collide with any
// future scope-local context registration the platform container might add.
type lifecycleCtx struct{ ctx context.Context }

// routes bundles ptr-form and value-form route slices. Both are derived
// from cfg at startup; the pointer form is used for transport-chain
// construction and the value form is used by the health aggregator.
type routes struct {
	ptr []*domain.Route
	val []domain.Route
}

func httpClientProvider(context.Context, *platform.Container) (*http.Client, error) {
	// A single client is reused by both the proxy transport and the health
	// checker so connection pools are shared rather than duplicated.
	// MaxIdleConnsPerHost is 20 (the default of 2 causes pool exhaustion under load).
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		},
	}, nil
}

func routesProvider(ctx context.Context, c *platform.Container) (*routes, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	ptr := cfg.ToDomainRoutes()
	val := make([]domain.Route, len(ptr))
	for i, r := range ptr {
		val[i] = *r
	}
	return &routes{ptr: ptr, val: val}, nil
}

func transportProvider(ctx context.Context, c *platform.Container) (ports.UpstreamTransport, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	rs := platform.MustResolve[*routes](ctx, c)
	client := platform.MustResolve[*http.Client](ctx, c)
	return buildTransportChain(cfg, rs.ptr, client), nil
}

func metricsRecorderProvider(context.Context, *platform.Container) (*prometheusout.MetricsRecorder, error) {
	// The Prometheus adapter registers its own isolated registry so multiple
	// instances can coexist in tests without registration conflicts.
	return prometheusout.NewMetricsRecorder(), nil
}

func gatewayServiceProvider(ctx context.Context, c *platform.Container) (*application.GatewayService, error) {
	log := platform.MustResolve[logging.Logger](ctx, c)
	rs := platform.MustResolve[*routes](ctx, c)
	resolver := static.NewResolver(rs.ptr)
	return application.NewGatewayService(resolver, log), nil
}

func healthAggregatorProvider(ctx context.Context, c *platform.Container) (*application.HealthAggregator, error) {
	rs := platform.MustResolve[*routes](ctx, c)
	client := platform.MustResolve[*http.Client](ctx, c)
	checker := healthhttp.NewChecker(client)
	return application.NewHealthAggregator(checker, rs.val), nil
}

func handlerProvider(ctx context.Context, c *platform.Container) (*inboundhttp.Handler, error) {
	gateway := platform.MustResolve[*application.GatewayService](ctx, c)
	transport := platform.MustResolve[ports.UpstreamTransport](ctx, c)
	recorder := platform.MustResolve[*prometheusout.MetricsRecorder](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	healthAgg := platform.MustResolve[*application.HealthAggregator](ctx, c)
	return inboundhttp.NewHandler(gateway, transport, recorder, log, healthAgg), nil
}

func mcpHandlerProvider(ctx context.Context, c *platform.Container) (*inboundhttp.MCPHandler, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	lc := platform.MustResolve[lifecycleCtx](ctx, c)
	transport := platform.MustResolve[ports.UpstreamTransport](ctx, c)

	mcpTools := cfg.MCPTools()
	mcpRateLimiter := memory.NewMCPRateLimiter(lc.ctx, cfg.MCP)
	var mcpDecider ports.MCPDecider
	if cfg.MCP.AnthropicAPIKey != "" {
		mcpDecider = anthropic.NewMCPDecider(cfg.MCP.AnthropicAPIKey, cfg.MCP.Model, log)
	} else {
		mcpDecider = static.NewMCPStaticDecider(mcpTools)
	}
	mcpGateway := application.NewMCPGatewayService(
		mcpDecider,
		mcpRateLimiter,
		mcpTools,
		cfg.MCP.ClientTiers,
		[]byte(cfg.MCP.JWTSigningKey),
		log,
	)
	return inboundhttp.NewMCPHandler(mcpGateway, transport, log), nil
}

func routerProvider(ctx context.Context, c *platform.Container) (http.Handler, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	lc := platform.MustResolve[lifecycleCtx](ctx, c)
	handler := platform.MustResolve[*inboundhttp.Handler](ctx, c)
	mcpHandler := platform.MustResolve[*inboundhttp.MCPHandler](ctx, c)
	recorder := platform.MustResolve[*prometheusout.MetricsRecorder](ctx, c)

	limiter, concLimiter := selectRateLimiter(lc.ctx, cfg)

	authMiddleware, err := buildAuthMiddleware(lc.ctx, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("setting up auth: %w", err)
	}

	tracingMiddleware, tracerShutdown, err := buildTracingMiddleware(cfg.Tracing)
	if err != nil {
		return nil, fmt.Errorf("setting up tracing: %w", err)
	}
	if tracerShutdown != nil {
		c.OnClose("tracer", tracerShutdown)
	}

	return inboundhttp.NewRouter(
		handler, mcpHandler, log, cfg.CORS,
		authMiddleware,
		buildIPFilterMiddleware(cfg, log),
		limiter, concLimiter, cfg.RateLimit.KeySource,
		recorder.Handler(),
		tracingMiddleware,
		buildCompressionMiddleware(cfg, log),
		buildCacheMiddleware(cfg),
	), nil
}

func selectRateLimiter(ctx context.Context, cfg *config.Config) (ports.RateLimiter, ports.ConcurrencyLimiter) {
	if !cfg.RateLimit.Enabled {
		return nil, nil
	}
	return buildRateLimiter(ctx, cfg)
}

func buildAuthMiddleware(ctx context.Context, cfg *config.Config, logger logging.Logger) (func(http.Handler) http.Handler, error) {
	if !cfg.Auth.Enabled {
		return nil, nil
	}
	verifier, err := buildAuthVerifier(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return inboundhttp.JWTMiddleware(verifier, cfg.Auth.PublicPaths, logger), nil
}

// buildAuthVerifier constructs the TokenVerifier implementation selected by
// cfg.Auth.Type. Strategy pattern: the container selects the concrete
// algorithm (HS256 or JWKS/RS256) so the inbound middleware never knows
// which is active.
//
// "jwks"  — RS256; keyfunc fetches and refreshes keys from cfg.Auth.JWKSURL.
//
//	ctx controls the background refresh goroutine lifetime.
//
// default — HS256; cfg.Auth.SigningKey must be non-empty.
func buildAuthVerifier(ctx context.Context, cfg *config.Config) (ports.TokenVerifier, error) {
	if cfg.Auth.Type == "jwks" {
		return jwksauth.New(ctx, cfg.Auth)
	}
	if cfg.Auth.SigningKey == "" {
		return nil, fmt.Errorf("auth.signing_key must be set when auth.type is %q", cfg.Auth.Type)
	}
	return hs256auth.NewVerifier([]byte(cfg.Auth.SigningKey)), nil
}

// buildRateLimiter selects and constructs the rate limiting adapter based
// on cfg.RateLimit.Strategy. Strategy "concurrency" populates only the
// ConcurrencyLimiter return value; all other strategies populate only the
// RateLimiter return value.
//
// ctx governs the token-bucket eviction goroutine lifetime
// (memory.NewRateLimiter). Other adapters are currently stateless and
// ignore it; pass it anyway so the signature remains consistent if any
// adapter adds background goroutines later.
//
// Extracted from the assembly path to keep cyclomatic complexity within
// the project limit.
func buildRateLimiter(ctx context.Context, cfg *config.Config) (ports.RateLimiter, ports.ConcurrencyLimiter) {
	rl := cfg.RateLimit
	window := time.Duration(rl.WindowSecs) * time.Second

	switch rl.Strategy {
	case "fixed_window":
		return fixedwindow.New(ctx, domain.FixedWindowRule{WindowRule: domain.WindowRule{
			RequestsPerWindow: rl.RequestsPerWindow,
			WindowDuration:    window,
		}}), nil

	case "sliding_window_log":
		return slidingwindowlog.New(ctx, domain.SlidingWindowLogRule{WindowRule: domain.WindowRule{
			RequestsPerWindow: rl.RequestsPerWindow,
			WindowDuration:    window,
		}}), nil

	case "sliding_window_counter":
		return slidingwindowcounter.New(ctx, domain.SlidingWindowCounterRule{WindowRule: domain.WindowRule{
			RequestsPerWindow: rl.RequestsPerWindow,
			WindowDuration:    window,
		}}), nil

	case "leaky_bucket":
		return leakybucket.New(ctx, domain.LeakyBucketRule{
			DrainRatePerSecond: rl.DrainRatePerSecond,
			QueueDepth:         rl.QueueDepth,
		}), nil

	case "concurrency":
		return nil, memory.NewConcurrencyLimiter(domain.ConcurrencyRule{
			MaxInFlight: rl.MaxInFlight,
		})

	default: // "token_bucket" and any unrecognized value
		// The eviction goroutine exits when ctx is canceled.
		return memory.NewRateLimiter(ctx, domain.RateLimitRule{
			RequestsPerSecond: rl.RequestsPerSecond,
			BurstSize:         rl.BurstSize,
		}), nil
	}
}

// buildIPFilterMiddleware returns an IP filter middleware when
// cfg.IPFilter.Enabled, otherwise nil.
func buildIPFilterMiddleware(cfg *config.Config, logger logging.Logger) func(http.Handler) http.Handler {
	if !cfg.IPFilter.Enabled {
		return nil
	}
	return inboundhttp.IPFilterMiddleware(cfg.IPFilter, logger)
}

// buildCompressionMiddleware returns a compression middleware when
// cfg.Compression.Enabled, otherwise nil.
func buildCompressionMiddleware(cfg *config.Config, logger logging.Logger) func(http.Handler) http.Handler {
	if !cfg.Compression.Enabled {
		return nil
	}
	return inboundhttp.CompressionMiddleware(cfg.Compression, logger)
}

// buildTransportChain assembles the outbound transport Decorator stack:
//
//	proxy.Transport ← URL-picker (weighted or round-robin) ← retry (optional) ← circuit breaker (optional)
//
// Request processing flows outermost → innermost: circuit breaker → retry → URL-picker → proxy.
// Retry wraps the URL-picker so each retry attempt may land on a different
// upstream endpoint when load balancing is active — a natural hedge
// against a single unhealthy instance.
func buildTransportChain(cfg *config.Config, ptrRoutes []*domain.Route, client *http.Client) ports.UpstreamTransport {
	var t ports.UpstreamTransport = proxy.NewTransport(client)

	// Use weighted URL selection when any route defines explicit weights.
	// weighted.Picker degrades to uniform random for equal/absent weights,
	// so it handles mixed-weight deployments without needing separate code
	// paths.
	if hasWeightedRoutes(ptrRoutes) {
		t = weighted.NewTransport(t, weighted.NewPicker())
	} else {
		t = roundrobin.NewTransport(t, roundrobin.NewPicker())
	}

	if cfg.Retry.Enabled {
		t = retryout.NewTransport(t, config.ToRetryConfig(cfg.Retry))
	}

	if cfg.CircuitBreaker.Enabled {
		t = circuitbreaker.NewTransport(t, cfg.CircuitBreaker)
	}
	return t
}

// buildCacheMiddleware returns a cache middleware when cfg.Cache.Enabled,
// otherwise nil.
func buildCacheMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	if !cfg.Cache.Enabled {
		return nil
	}
	cache := memory.NewCache(cfg.Cache.MaxEntries)
	return inboundhttp.CacheMiddleware(cache, cfg.Cache)
}

// hasWeightedRoutes reports whether any route in the pool carries explicit
// per-URL weights. Used by buildTransportChain to select the URL-picker
// strategy.
func hasWeightedRoutes(routes []*domain.Route) bool {
	for _, r := range routes {
		if len(r.Upstream.Weights) > 0 {
			return true
		}
	}
	return false
}

// buildTracingMiddleware sets up the OTel trace provider and returns an
// HTTP middleware closure that wraps each handler with span creation and
// W3C TraceContext extraction. When cfg.Enabled is false, the middleware
// is nil and the shutdown function is a no-op; the provider is discarded.
func buildTracingMiddleware(cfg config.TracingConfig) (func(http.Handler) http.Handler, func(context.Context) error, error) {
	tp, shutdown, err := observability.SetupTracing(cfg)
	if err != nil {
		return nil, nil, err
	}
	if !cfg.Enabled {
		return nil, shutdown, nil
	}
	mw := func(next http.Handler) http.Handler {
		return otelhttp.NewHandler(next, "api-gateway",
			otelhttp.WithTracerProvider(tp),
			otelhttp.WithPropagators(otel.GetTextMapPropagator()),
		)
	}
	return mw, shutdown, nil
}
