// Package container is the Dependency Injection root for the api-gateway.
//
// Design: Facade pattern — New() is the single entry point that constructs and
// wires every concrete adapter without exposing internal complexity to callers.
// Application code and tests interact only with the Container struct.
package container

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	hs256auth "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/inbound/auth/hs256"
	jwksauth "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/inbound/auth/jwks"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/inbound/http"
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

// Container holds all wired service dependencies for the api-gateway.
//
// Shutdown must be called on process exit (after the HTTP server drains) to
// flush any in-flight telemetry spans. Pass the graceful-shutdown context so
// the flush is bounded by the same deadline as the HTTP server drain.
//
// SetReady(false) begins the two-phase graceful shutdown sequence: the /health
// endpoint returns 503 immediately, signalling the load balancer to stop routing
// new traffic. After the LB drain window elapses, call server.Shutdown followed
// by Shutdown to complete the sequence.
type Container struct {
	Logger   logging.Logger
	Handler  http.Handler
	Config   *config.Config
	Shutdown func(context.Context) error
	SetReady func(bool)
}

// New constructs a fully wired Container.
//
// ctx controls the lifecycle of background goroutines started here (the
// rate-limiter eviction loop). Cancel it on shutdown to release resources.
//
// Adapter selection uses the Strategy pattern throughout: every field in the
// handler and router is a port interface. The concrete type is chosen here in
// the Facade and is invisible to application logic.
//
//   - RouteResolver:     static.Resolver — loads routes from config at startup
//   - UpstreamTransport: proxy.Transport — httputil.ReverseProxy with pooled client
//     wrapped by roundrobin.Transport (URL selection, always active)
//     optionally wrapped by circuitbreaker.Transport (Decorator pattern)
//   - MetricsRecorder:   prometheusout.MetricsRecorder — exposes /metrics
//   - HealthChecker:     healthhttp.Checker — probes each upstream's /health
//   - RateLimiter:       strategy selected by cfg.RateLimit.Strategy; nil when disabled
func New(ctx context.Context, cfg *config.Config, logger logging.Logger) (*Container, error) {
	// --- Route resolver (static; restart required to pick up config changes) ---
	ptrRoutes := cfg.ToDomainRoutes()
	resolver := static.NewResolver(ptrRoutes)

	// GatewayService owns route-resolution logic; adapters delegate to it.
	gateway := application.NewGatewayService(resolver, logger)

	// --- Shared HTTP client ---
	// A single client is reused by both the proxy transport and the health checker
	// so connection pools are shared rather than duplicated.
	// MaxIdleConnsPerHost is 20 (the default of 2 causes pool exhaustion under load).
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// --- Upstream transport chain (innermost to outermost) ---
	//
	// The Decorator layers are applied inside-out. Request processing flows
	// outermost → innermost; the chain is:
	//
	//   [circuit breaker] → [round-robin | weighted] → [proxy]
	//
	// The URL-selection layer (round-robin or weighted) sets route.Upstream.URL
	// from the pool before passing the copy to the proxy transport.
	// The circuit breaker (when enabled) sits outside both so it can short-
	// circuit the entire attempt — including URL selection — when the route
	// is in the Open state.
	transport := buildTransportChain(cfg, ptrRoutes, httpClient)

	// --- Metrics (Strategy pattern: Prometheus recorder) ---
	// The Prometheus adapter registers its own isolated registry so multiple
	// instances can coexist in tests without registration conflicts.
	// To fall back to the no-op recorder, replace with noop.NewMetricsRecorder()
	// and pass nil as metricsHandler below.
	promRecorder := prometheusout.NewMetricsRecorder()

	// --- Health aggregation ---
	// healthhttp.Checker is the outbound port that probes each upstream.
	// HealthAggregator fans the checks out concurrently and collapses results
	// into a single HealthReport (see application/health.go).
	checker := healthhttp.NewChecker(httpClient)

	// The aggregator takes []domain.Route (values); ToDomainRoutes returns pointers.
	// Dereference once here at startup — routes do not change while running.
	routes := make([]domain.Route, len(ptrRoutes))
	for i, r := range ptrRoutes {
		routes[i] = *r
	}
	healthAgg := application.NewHealthAggregator(checker, routes)

	// --- Rate limiter (Strategy pattern: algorithm selected by config) ---
	// Passing nil to NewRouter skips the RateLimitMiddleware decorator entirely,
	// so disabled rate limiting has zero overhead on the request path.
	// buildRateLimiter selects the concrete algorithm based on cfg.RateLimit.Strategy.
	var limiter ports.RateLimiter
	var concLimiter ports.ConcurrencyLimiter
	if cfg.RateLimit.Enabled {
		limiter, concLimiter = buildRateLimiter(ctx, cfg)
	}

	// --- JWT auth middleware (Decorator + Strategy pattern: nil = disabled) ---
	// The middleware is constructed here in the Facade so the inbound adapter
	// receives a plain func(http.Handler) http.Handler — no JWT types leak out.
	// buildAuthVerifier selects the concrete TokenVerifier strategy based on
	// cfg.Auth.Type ("hs256" or "jwks") without the router knowing which.
	// When auth is disabled, authMiddleware is nil and NewRouter skips it.
	var authMiddleware func(http.Handler) http.Handler
	if cfg.Auth.Enabled {
		verifier, authErr := buildAuthVerifier(ctx, cfg)
		if authErr != nil {
			return nil, fmt.Errorf("setting up auth: %w", authErr)
		}
		authMiddleware = inboundhttp.JWTMiddleware(verifier, cfg.Auth.PublicPaths, logger)
	}

	// --- Distributed tracing (OTel, Decorator pattern: nil = disabled) ---
	// The middleware closure is constructed here so the inbound adapter receives a
	// plain func(http.Handler) http.Handler — no OTel types leak into routes.go.
	tracingMiddleware, tracerShutdown, err := buildTracingMiddleware(cfg.Tracing)
	if err != nil {
		return nil, fmt.Errorf("setting up tracing: %w", err)
	}

	// --- Wire the inbound HTTP layer ---
	// Handler is thin: it extracts HTTP primitives and delegates to port interfaces.
	// Router applies the middleware chain (Decorator pattern) and wires system routes.
	handler := inboundhttp.NewHandler(gateway, transport, promRecorder, logger, healthAgg)
	router := inboundhttp.NewRouter(
		handler, logger, cfg.CORS,
		authMiddleware,
		buildIPFilterMiddleware(cfg, logger),
		limiter, concLimiter, cfg.RateLimit.KeySource,
		promRecorder.Handler(),
		tracingMiddleware,
		buildCompressionMiddleware(cfg),
		buildCacheMiddleware(cfg),
	)

	return &Container{
		Logger:   logger,
		Handler:  router,
		Config:   cfg,
		Shutdown: tracerShutdown,
		SetReady: handler.SetReady,
	}, nil
}

// buildAuthVerifier constructs the TokenVerifier implementation selected by
// cfg.Auth.Type. Strategy pattern: the container selects the concrete algorithm
// (HS256 or JWKS/RS256) so the inbound middleware never knows which is active.
//
// "jwks"  — RS256; keyfunc fetches and refreshes keys from cfg.Auth.JWKSUrl.
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

// buildRateLimiter selects and constructs the rate limiting adapter based on
// cfg.RateLimit.Strategy. Returns (nil, nil) if the strategy is unrecognised
// or the enabled flag is false (the caller guards the enabled check).
//
// Strategy "concurrency" populates only the ConcurrencyLimiter return value;
// all other strategies populate only the RateLimiter return value.
//
// Extracted from New to keep its cyclomatic complexity within the project limit.
func buildRateLimiter(ctx context.Context, cfg *config.Config) (ports.RateLimiter, ports.ConcurrencyLimiter) {
	rl := cfg.RateLimit
	window := time.Duration(rl.WindowSecs) * time.Second

	switch rl.Strategy {
	case "fixed_window":
		return fixedwindow.New(domain.FixedWindowRule{
			RequestsPerWindow: rl.RequestsPerWindow,
			WindowDuration:    window,
		}), nil

	case "sliding_window_log":
		return slidingwindowlog.New(domain.SlidingWindowLogRule{
			RequestsPerWindow: rl.RequestsPerWindow,
			WindowDuration:    window,
		}), nil

	case "sliding_window_counter":
		return slidingwindowcounter.New(domain.SlidingWindowCounterRule{
			RequestsPerWindow: rl.RequestsPerWindow,
			WindowDuration:    window,
		}), nil

	case "leaky_bucket":
		return leakybucket.New(domain.LeakyBucketRule{
			DrainRatePerSecond: rl.DrainRatePerSecond,
			QueueDepth:         rl.QueueDepth,
		}), nil

	case "concurrency":
		return nil, memory.NewConcurrencyLimiter(domain.ConcurrencyRule{
			MaxInFlight: rl.MaxInFlight,
		})

	default: // "token_bucket" and any unrecognised value
		// The eviction goroutine exits when ctx is cancelled.
		return memory.NewRateLimiter(ctx, domain.RateLimitRule{
			RequestsPerSecond: rl.RequestsPerSecond,
			BurstSize:         rl.BurstSize,
		}), nil
	}
}

// buildIPFilterMiddleware returns an IP filter middleware when cfg.IPFilter.Enabled,
// otherwise nil. Extracted from New to keep its cyclomatic complexity within limit.
func buildIPFilterMiddleware(cfg *config.Config, logger logging.Logger) func(http.Handler) http.Handler {
	if !cfg.IPFilter.Enabled {
		return nil
	}
	return inboundhttp.IPFilterMiddleware(cfg.IPFilter, logger)
}

// buildCompressionMiddleware returns a compression middleware when cfg.Compression.Enabled,
// otherwise nil. Extracted from New to keep its cyclomatic complexity within limit.
func buildCompressionMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	if !cfg.Compression.Enabled {
		return nil
	}
	return inboundhttp.CompressionMiddleware(cfg.Compression)
}

// buildTransportChain assembles the outbound transport Decorator stack:
//
//	proxy.Transport ← URL-picker (weighted or round-robin) ← retry (optional) ← circuit breaker (optional)
//
// Request processing flows outermost → innermost: circuit breaker → retry → URL-picker → proxy.
// Retry wraps the URL-picker so each retry attempt may land on a different upstream endpoint
// when load balancing is active — a natural hedge against a single unhealthy instance.
//
// Extracted from New to keep its cyclomatic complexity within the project limit.
func buildTransportChain(cfg *config.Config, routes []*domain.Route, client *http.Client) ports.UpstreamTransport {
	var t ports.UpstreamTransport = proxy.NewTransport(client)

	// Use weighted URL selection when any route defines explicit weights.
	// weighted.Picker degrades to uniform random for equal/absent weights, so
	// it handles mixed-weight deployments without needing separate code paths.
	if hasWeightedRoutes(routes) {
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
// otherwise nil. Extracted from New to keep its cyclomatic complexity within limit.
func buildCacheMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	if !cfg.Cache.Enabled {
		return nil
	}
	cache := memory.NewCache(cfg.Cache.MaxEntries)
	return inboundhttp.CacheMiddleware(cache, cfg.Cache)
}

// hasWeightedRoutes reports whether any route in the pool carries explicit per-URL
// weights. Used by buildTransportChain to select the URL-picker strategy.
func hasWeightedRoutes(routes []*domain.Route) bool {
	for _, r := range routes {
		if len(r.Upstream.Weights) > 0 {
			return true
		}
	}
	return false
}

// buildTracingMiddleware sets up the OTel trace provider and returns an HTTP
// middleware closure that wraps each handler with span creation and W3C
// TraceContext extraction. When cfg.Enabled is false, both the middleware and
// the shutdown function are no-ops, and the provider is discarded.
//
// Extracted from New to keep its cyclomatic complexity within the project limit.
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
