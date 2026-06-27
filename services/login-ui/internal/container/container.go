// Package container wires the login-ui service's dependencies through the
// platform DI container. Resolution from the returned container is
// restricted to the composition root in cmd/main.go; business code
// receives its dependencies via constructor parameters.
package container

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"
	platform "github.com/jedi-knights/go-platform/container"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/outbound/authserver"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/outbound/identityservice"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/outbound/lago"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/config"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/observability"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
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
	platform.Register(c, httpClientProvider)
	platform.Register(c, auditEmitterProvider)
	platform.Register(c, userAuthenticatorProvider)
	platform.Register(c, authCodeIssuerProvider)
	platform.Register(c, billingClientProvider)
	platform.Register(c, handlerProvider)

	if err := c.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrapping container: %w", err)
	}
	return c, nil
}

func handlerProvider(ctx context.Context, c *platform.Container) (*inboundhttp.Handler, error) {
	logger := platform.MustResolve[logging.Logger](ctx, c)
	userAuth, _ := platform.Resolve[ports.UserAuthenticator](ctx, c)
	codeIssuer, _ := platform.Resolve[ports.AuthCodeIssuer](ctx, c)
	emitter := platform.MustResolve[audit.Emitter](ctx, c)
	cfg := platform.MustResolve[*config.Config](ctx, c)
	billing, _ := platform.Resolve[ports.BillingClient](ctx, c)
	h := inboundhttp.NewHandler(userAuth, codeIssuer, logger).WithAudit(emitter, "login-ui")
	if billing != nil {
		h = h.WithBilling(billing, cfg.Billing.SuccessURL, cfg.Billing.CancelURL)
	}
	return h, nil
}

// billingClientProvider wires the Lago billing client when
// LOGIN_UI_BILLING_LAGO_URL is set. When unset (or when the API key is
// missing) the provider returns (nil, nil) — the platform container
// resolves the nil interface and the billing routes degrade to 503. This
// is the documented degradation path for environments that have not yet
// stood up Lago.
func billingClientProvider(ctx context.Context, c *platform.Container) (ports.BillingClient, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	if cfg.Billing.LagoURL == "" || cfg.Billing.LagoAPIKey == "" {
		return nil, nil //nolint:nilnil // documented degradation path
	}
	httpClient := platform.MustResolve[*http.Client](ctx, c)
	return lago.New(cfg.Billing.LagoURL, cfg.Billing.LagoAPIKey, httpClient), nil
}

// auditEmitterProvider builds the audit.Emitter per ADR-0018 + ADR-0019.
// When LOGIN_UI_AUDIT_DURABLE_DSN is set the emitter writes through a
// Postgres durable sink in addition to the best-effort stderr sink, and
// the returned pool is registered as an OnClose hook for graceful
// shutdown.
func auditEmitterProvider(ctx context.Context, c *platform.Container) (audit.Emitter, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	wiring, err := observability.NewAuditEmitter(ctx, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if wiring.Pool != nil {
		pool := wiring.Pool
		c.OnClose("audit-durable", func(_ context.Context) error {
			pool.Close()
			return nil
		})
	}
	return wiring.Emitter, nil
}

// httpClientProvider returns a single *http.Client shared by every outbound
// adapter. 10s timeout matches every other service in the platform — long
// enough for an upstream cold start, short enough that a stuck dependency
// surfaces as a sign-in failure rather than a hung request.
func httpClientProvider(context.Context, *platform.Container) (*http.Client, error) {
	return &http.Client{Timeout: 10 * time.Second}, nil
}

// userAuthenticatorProvider wires the identity-service adapter when
// LOGIN_UI_IDENTITY_SERVICE_URL is set. When unset the provider returns
// (nil, nil) — the platform container resolves the nil interface and the
// handler degrades to 503. This lets local development run without
// identity-service.
func userAuthenticatorProvider(ctx context.Context, c *platform.Container) (ports.UserAuthenticator, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	if cfg.IdentityService.URL == "" {
		return nil, nil //nolint:nilnil // documented degradation path
	}
	httpClient := platform.MustResolve[*http.Client](ctx, c)
	return identityservice.NewAuthenticator(cfg.IdentityService.URL, httpClient), nil
}

// authCodeIssuerProvider wires the auth-server /internal/issue-code adapter
// when both LOGIN_UI_AUTH_SERVER_URL and LOGIN_UI_AUTH_SERVER_SERVICE_TOKEN
// are set. A missing service token is treated the same as a missing URL:
// the adapter is not wired and the handler degrades to 503.
func authCodeIssuerProvider(ctx context.Context, c *platform.Container) (ports.AuthCodeIssuer, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	if cfg.AuthServer.URL == "" || cfg.AuthServer.ServiceToken == "" {
		return nil, nil //nolint:nilnil // documented degradation path
	}
	httpClient := platform.MustResolve[*http.Client](ctx, c)
	return authserver.NewIssueCodeClient(cfg.AuthServer.URL, cfg.AuthServer.ServiceToken, httpClient), nil
}
