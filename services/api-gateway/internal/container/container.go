package container

import (
	"net/http"
	"time"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/noop"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/proxy"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/static"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/application"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
)

// Container holds all wired service dependencies for the api-gateway.
type Container struct {
	Logger  logging.Logger
	Handler http.Handler
	Config  *config.Config
}

// New constructs a fully wired Container.
//
// Adapter selection:
//   - RouteResolver: static config adapter (reads routes from cfg at startup)
//   - UpstreamTransport: reverse proxy adapter (httputil.ReverseProxy with shared client)
//   - MetricsRecorder: no-op adapter (replace with Prometheus/OTEL adapter for production metrics)
func New(cfg *config.Config, logger logging.Logger) (*Container, error) {
	routes := cfg.ToDomainRoutes()

	resolver := static.NewResolver(routes)
	gateway := application.NewGatewayService(resolver, logger)

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	transport := proxy.NewTransport(httpClient)
	metrics := noop.NewMetricsRecorder()

	handler := inboundhttp.NewHandler(gateway, transport, metrics, logger)
	router := inboundhttp.NewRouter(handler, logger)

	return &Container{
		Logger:  logger,
		Handler: router,
		Config:  cfg,
	}, nil
}
