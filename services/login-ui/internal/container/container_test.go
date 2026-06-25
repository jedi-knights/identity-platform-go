package container_test

import (
	"context"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"
	platform "github.com/jedi-knights/go-platform/container"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/config"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/container"
)

func quietLogger(t *testing.T) logging.Logger {
	t.Helper()
	return logging.New(logging.Config{Level: "error", Format: "text", Environment: "test"})
}

func TestNew_NilConfig(t *testing.T) {
	_, err := container.New(context.Background(), nil, quietLogger(t))
	if err == nil {
		t.Fatal("expected error for nil config, got nil")
	}
}

func TestNew_NilLogger(t *testing.T) {
	_, err := container.New(context.Background(), &config.Config{}, nil)
	if err == nil {
		t.Fatal("expected error for nil logger, got nil")
	}
}

func TestNew_ResolvesHandler(t *testing.T) {
	// Arrange / Act
	ctx := context.Background()
	c, err := container.New(ctx, &config.Config{}, quietLogger(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Assert
	if h := platform.MustResolve[*inboundhttp.Handler](ctx, c); h == nil {
		t.Fatal("Handler is nil")
	}
}
