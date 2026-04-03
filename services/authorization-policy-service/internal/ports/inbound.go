package ports

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/application"
)

// PolicyEvaluator evaluates authorization policies
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, req application.EvaluationRequest) (*application.EvaluationResponse, error)
}
