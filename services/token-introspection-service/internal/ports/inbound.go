package ports

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
)

type Introspector interface {
	Introspect(ctx context.Context, raw string) (*domain.IntrospectionResult, error)
}
