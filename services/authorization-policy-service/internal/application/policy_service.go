package application

import (
	"context"

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
		return &domain.EvaluationResponse{Allowed: false, Reason: "no policy found for subject"}, nil
	}

	spec := NewPermissionSpecification(ctx, s.roleRepo, req.Resource, req.Action)

	if spec.IsSatisfiedBy(policy.Roles) {
		return &domain.EvaluationResponse{Allowed: true}, nil
	}

	return &domain.EvaluationResponse{Allowed: false, Reason: "insufficient permissions"}, nil
}
