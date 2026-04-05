package ports

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// PolicyEvaluator evaluates authorization policies.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, req domain.EvaluationRequest) (*domain.EvaluationResponse, error)
}

// SubjectPermissionsReader resolves the full RBAC state for a subject.
// Used by auth-server at token issuance to embed roles and permissions in the JWT.
type SubjectPermissionsReader interface {
	GetSubjectPermissions(ctx context.Context, subjectID string) (*domain.SubjectPermissions, error)
}
