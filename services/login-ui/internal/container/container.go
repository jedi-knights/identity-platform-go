// Package container wires the login-ui service's dependencies through the
// platform DI container. Resolution from the returned container is
// restricted to the composition root in cmd/main.go; business code
// receives its dependencies via constructor parameters.
package container

import (
	"context"
	"fmt"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"
	platform "github.com/jedi-knights/go-platform/container"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/config"
)

// New constructs and bootstraps a platform.Container wired with every
// dependency this service needs. Today that is just config + logger +
// Handler; the sign-in flow lands in a subsequent commit and registers
// the identity-service client and the auth-server /internal/issue-code
// client on top.
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
	platform.Register(c, handlerProvider)

	if err := c.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrapping container: %w", err)
	}
	return c, nil
}

func handlerProvider(context.Context, *platform.Container) (*inboundhttp.Handler, error) {
	return inboundhttp.NewHandler(), nil
}
