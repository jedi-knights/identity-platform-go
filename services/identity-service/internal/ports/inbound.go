package ports

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/application"
)

// Authenticator is the inbound port for user authentication
type Authenticator interface {
	Login(ctx context.Context, req application.LoginRequest) (*application.LoginResponse, error)
}

// UserRegistrar is the inbound port for user registration
type UserRegistrar interface {
	Register(ctx context.Context, req application.RegisterRequest) (*application.RegisterResponse, error)
}
