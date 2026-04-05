package container

import (
	"fmt"
	"net/url"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/adapters/inbound/http"
	jwtadapter "github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/adapters/outbound/jwt"
	redisadapter "github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/adapters/outbound/redis"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
)

// Container holds the wired-up dependencies for the token introspection service.
type Container struct {
	Logger  logging.Logger
	Handler *inboundhttp.Handler
	Config  *config.Config
}

// redisAddr extracts the host:port from a Redis URL for safe logging.
// If the URL cannot be parsed, the original string is returned so no information is lost.
func redisAddr(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Host
}

// New wires up all service dependencies and returns a ready-to-use Container.
// If INTROSPECT_REDIS_URL is set, a Redis-backed revocation checker is wired in;
// otherwise revocation is disabled and tokens are accepted until their JWT expiry.
func New(cfg *config.Config, logger logging.Logger) (*Container, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	var revocation domain.RevocationChecker
	if cfg.Redis.URL != "" {
		// Log only the host:port — the URL may embed a password (redis://:pass@host/db).
		redisAddr := redisAddr(cfg.Redis.URL)
		// No startup ping: the Redis client connects lazily. A failed ping here would
		// prevent the service from starting even when Redis is temporarily unavailable,
		// which violates the fail-closed contract (token treated as inactive, not service down).
		logger.Info("using Redis revocation check", "addr", redisAddr)
		client, err := redisadapter.NewClient(cfg.Redis.URL)
		if err != nil {
			return nil, fmt.Errorf("connecting to Redis: %w", err)
		}
		revocation = redisadapter.NewRevocationStore(client)
	} else {
		logger.Info("Redis revocation check disabled (INTROSPECT_REDIS_URL not set); revoked tokens will be accepted until expiry")
	}

	validator := jwtadapter.NewValidator([]byte(cfg.JWT.SigningKey))
	svc := application.NewIntrospectionService(validator, revocation)
	handler := inboundhttp.NewHandler(svc, logger)

	return &Container{
		Logger:  logger,
		Handler: handler,
		Config:  cfg,
	}, nil
}
