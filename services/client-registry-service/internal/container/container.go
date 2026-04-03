package container

import (
	"fmt"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/config"
)

// Container holds all wired service dependencies.
type Container struct {
	Logger  logging.Logger
	Handler *inboundhttp.Handler
	Config  *config.Config
}

// New creates and wires all dependencies.
func New(cfg *config.Config, logger logging.Logger) (*Container, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	clientRepo := memory.NewClientRepository()
	clientSvc := application.NewClientService(clientRepo)
	handler := inboundhttp.NewHandler(clientSvc, clientSvc, clientSvc, clientSvc, logger)

	return &Container{
		Logger:  logger,
		Handler: handler,
		Config:  cfg,
	}, nil
}
