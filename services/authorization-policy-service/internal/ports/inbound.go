package ports

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// PolicyEvaluator evaluates authorization policies.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, req domain.EvaluationRequest) (*domain.EvaluationResponse, error)
}
