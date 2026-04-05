package application

import (
	"context"
	"fmt"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// PolicyService evaluates authorization policies.
type PolicyService struct {
	policyRepo domain.PolicyRepository
	roleRepo   domain.RoleRepository
}

// NewPolicyService creates a PolicyService backed by the given repositories.
func NewPolicyService(policyRepo domain.PolicyRepository, roleRepo domain.RoleRepository) *PolicyService {
	return &PolicyService{policyRepo: policyRepo, roleRepo: roleRepo}
}

// Evaluate checks whether the subject in req is permitted to perform the requested action.
func (s *PolicyService) Evaluate(ctx context.Context, req domain.EvaluationRequest) (*domain.EvaluationResponse, error) {
	policy, err := s.policyRepo.FindBySubject(ctx, req.SubjectID)
	if err != nil {
		if apperrors.IsNotFound(err) {
			return &domain.EvaluationResponse{Allowed: false, Reason: "no policy found for subject"}, nil
		}
		return nil, fmt.Errorf("finding policy for subject %q: %w", req.SubjectID, err)
	}

	spec := NewPermissionSpecification(s.roleRepo, req.Resource, req.Action)

	if spec.IsSatisfiedBy(ctx, policy.Roles) {
		return &domain.EvaluationResponse{Allowed: true}, nil
	}

	return &domain.EvaluationResponse{Allowed: false, Reason: "insufficient permissions"}, nil
}
