//go:build unit

package container_test

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"
	platform "github.com/jedi-knights/go-platform/container"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/container"
)

func TestNew_ReturnsContainerWithHandler(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Host: "0.0.0.0", Port: 8080},
		Log:    config.LogConfig{Level: "info", Format: "json"},
		Routes: []config.RouteConfig{
			{
				Name:     "identity",
				Match:    config.MatchConfig{PathPrefix: "/api/identity"},
				Upstream: config.UpstreamConfig{URL: "http://identity-service:8080"},
			},
		},
	}
	logger := logging.New(logging.Config{Output: io.Discard})

	// context.Background() is the correct root context for tests; in production
	// main.go passes a context canceled on SIGTERM to stop background goroutines.
	ctx := context.Background()
	ctr, err := container.New(ctx, cfg, logger)

	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if ctr == nil {
		t.Fatal("New() returned nil container")
	}
	if router := platform.MustResolve[http.Handler](ctx, ctr); router == nil {
		t.Error("router (http.Handler) resolved as nil")
	}
	if handler := platform.MustResolve[*inboundhttp.Handler](ctx, ctr); handler == nil {
		t.Error("*inboundhttp.Handler resolved as nil")
	}
	if log := platform.MustResolve[logging.Logger](ctx, ctr); log == nil {
		t.Error("logger resolved as nil")
	}
	if gotCfg := platform.MustResolve[*config.Config](ctx, ctr); gotCfg != cfg {
		t.Error("expected the same Config pointer that was passed to New")
	}
}

func TestNew_WorksWithNoRoutes(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Host: "0.0.0.0", Port: 8080},
	}
	logger := logging.New(logging.Config{Output: io.Discard})

	ctr, err := container.New(context.Background(), cfg, logger)

	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if ctr == nil {
		t.Fatal("New() returned nil container")
	}
}
