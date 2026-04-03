package container

import (
	"fmt"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/adapters/inbound/http"
	jwtadapter "github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/adapters/outbound/jwt"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/config"
)

type Container struct {
	Logger  logging.Logger
	Handler *inboundhttp.Handler
	Config  *config.Config
}

func New(cfg *config.Config, logger logging.Logger) (*Container, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	validator := jwtadapter.NewValidator([]byte(cfg.JWT.SigningKey))
	svc := application.NewIntrospectionService(validator)
	handler := inboundhttp.NewHandler(svc, logger)

	return &Container{
		Logger:  logger,
		Handler: handler,
		Config:  cfg,
	}, nil
}
