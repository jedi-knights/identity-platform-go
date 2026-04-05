package container

import (
	"fmt"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/config"
)

type Container struct {
	Logger     logging.Logger
	Handler    *inboundhttp.Handler
	Config     *config.Config
	SigningKey []byte
}

func New(cfg *config.Config, logger logging.Logger) (*Container, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	repo := memory.NewResourceRepository()
	svc := application.NewResourceService(repo)
	handler := inboundhttp.NewHandler(svc, svc, svc, logger)

	return &Container{
		Logger:     logger,
		Handler:    handler,
		Config:     cfg,
		SigningKey: []byte(cfg.JWT.SigningKey),
	}, nil
}
