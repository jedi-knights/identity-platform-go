//go:build unit

package container_test

import (
	"context"
	"io"
	"testing"

	"github.com/ocrosby/identity-platform-go/libs/logging"
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
	logger := logging.NewLogger(logging.Config{Output: io.Discard})

	// context.Background() is the correct root context for tests; in production
	// main.go passes a context cancelled on SIGTERM to stop background goroutines.
	ctr, err := container.New(context.Background(), cfg, logger)

	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if ctr == nil {
		t.Fatal("New() returned nil container")
	}
	if ctr.Handler == nil {
		t.Error("container.Handler is nil")
	}
	if ctr.Logger == nil {
		t.Error("container.Logger is nil")
	}
	if ctr.Config == nil {
		t.Error("container.Config is nil")
	}
}

func TestNew_WorksWithNoRoutes(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Host: "0.0.0.0", Port: 8080},
	}
	logger := logging.NewLogger(logging.Config{Output: io.Discard})

	ctr, err := container.New(context.Background(), cfg, logger)

	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if ctr == nil {
		t.Fatal("New() returned nil container")
	}
}
