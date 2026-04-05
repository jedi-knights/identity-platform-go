package application

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
)

type IntrospectionService struct {
	validator domain.TokenValidator
}

func NewIntrospectionService(validator domain.TokenValidator) *IntrospectionService {
	return &IntrospectionService{validator: validator}
}

func (s *IntrospectionService) Introspect(ctx context.Context, raw string) (*domain.IntrospectionResult, error) {
	return s.validator.Validate(ctx, raw)
}
