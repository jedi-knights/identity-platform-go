package application

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// EvaluationRequest is the input for policy evaluation.
type EvaluationRequest struct {
	SubjectID string `json:"subject_id"`
	Resource  string `json:"resource"`
	Action    string `json:"action"`
}

// EvaluationResponse is the result of policy evaluation.
type EvaluationResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// PolicyService evaluates authorization policies.
type PolicyService struct {
	policyRepo domain.PolicyRepository
	roleRepo   domain.RoleRepository
}

func NewPolicyService(policyRepo domain.PolicyRepository, roleRepo domain.RoleRepository) *PolicyService {
	return &PolicyService{policyRepo: policyRepo, roleRepo: roleRepo}
}

func (s *PolicyService) Evaluate(_ context.Context, req EvaluationRequest) (*EvaluationResponse, error) {
	subject := &domain.Subject{ID: req.SubjectID}
	_ = subject

	policy, err := s.policyRepo.FindBySubject(req.SubjectID)
	if err != nil {
		return &EvaluationResponse{Allowed: false, Reason: "no policy found for subject"}, nil
	}

	spec := NewPermissionSpecification(s.roleRepo, req.Resource, req.Action)

	if spec.IsSatisfiedBy(policy.Roles) {
		return &EvaluationResponse{Allowed: true}, nil
	}

	return &EvaluationResponse{Allowed: false, Reason: "insufficient permissions"}, nil
}
