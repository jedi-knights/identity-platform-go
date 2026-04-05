package container

import (
	"fmt"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/config"
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
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	policyRepo := memory.NewPolicyRepository()
	roleRepo := memory.NewRoleRepository()
	svc := application.NewPolicyService(policyRepo, roleRepo)
	handler := inboundhttp.NewHandler(svc, logger)

	return &Container{
		Logger:  logger,
		Handler: handler,
		Config:  cfg,
	}, nil
}
