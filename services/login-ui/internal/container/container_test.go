package container_test

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// forgotPasswordStatus boots a container from cfg and reports the status of
// GET /forgot-password, which is 503 unless the password-reset port is wired.
func forgotPasswordStatus(t *testing.T, cfg *config.Config) int {
	t.Helper()
	ctx := context.Background()
	logger := quietLogger(t)
	c, err := container.New(ctx, cfg, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	router := inboundhttp.NewRouter(platform.MustResolve[*inboundhttp.Handler](ctx, c), logger)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/forgot-password", nil))
	return rec.Code
}

func TestNew_PasswordResetWiredWhenIdentityServiceURLSet(t *testing.T) {
	cfg := &config.Config{IdentityService: config.IdentityServiceConfig{URL: "http://identity.internal:8081"}}

	if got := forgotPasswordStatus(t, cfg); got != http.StatusOK {
		t.Errorf("GET /forgot-password = %d, want 200 when identity-service is configured", got)
	}
}

func TestNew_PasswordResetDisabledWithoutIdentityServiceURL(t *testing.T) {
	if got := forgotPasswordStatus(t, &config.Config{}); got != http.StatusServiceUnavailable {
		t.Errorf("GET /forgot-password = %d, want 503 when identity-service is not configured", got)
	}
}
