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

// GetSubjectPermissions returns all roles assigned to subjectID and the full set of
// permissions those roles grant. Permissions are formatted as "resource:action".
// Returns an empty SubjectPermissions (not an error) when the subject has no policy.
func (s *PolicyService) GetSubjectPermissions(ctx context.Context, subjectID string) (*domain.SubjectPermissions, error) {
	policy, err := s.policyRepo.FindBySubject(ctx, subjectID)
	if err != nil {
		if apperrors.IsNotFound(err) {
			return &domain.SubjectPermissions{SubjectID: subjectID, Roles: []string{}, Permissions: []string{}}, nil
		}
		return nil, fmt.Errorf("finding policy for subject %q: %w", subjectID, err)
	}

	permissions, err := s.collectPermissions(ctx, policy.Roles)
	if err != nil {
		return nil, err
	}

	return &domain.SubjectPermissions{
		SubjectID:   subjectID,
		Roles:       policy.Roles,
		Permissions: permissions,
	}, nil
}

// collectPermissions resolves the deduplicated permission set for a list of role names.
// Unknown roles (not found in the repository) are silently skipped — see CLAUDE.md.
// Permissions are formatted as "resource:action". Extracted from GetSubjectPermissions
// to keep its cyclomatic complexity within bounds.
func (s *PolicyService) collectPermissions(ctx context.Context, roles []string) ([]string, error) {
	seen := make(map[string]struct{})
	var permissions []string
	for _, roleName := range roles {
		role, err := s.roleRepo.FindByName(ctx, roleName)
		if err != nil {
			if apperrors.IsNotFound(err) {
				continue // role assigned but not defined — skip silently
			}
			return nil, fmt.Errorf("finding role %q: %w", roleName, err)
		}
		for _, perm := range role.Permissions {
			key := perm.Resource + ":" + perm.Action
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				permissions = append(permissions, key)
			}
		}
	}
	if permissions == nil {
		permissions = []string{}
	}
	return permissions, nil
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

	spec := newPermissionSpecification(s.roleRepo, req.Resource, req.Action)

	allowed, err := spec.IsSatisfiedBy(ctx, policy.Roles)
	if err != nil {
		return nil, fmt.Errorf("evaluating permissions: %w", err)
	}
	if allowed {
		return &domain.EvaluationResponse{Allowed: true}, nil
	}

	return &domain.EvaluationResponse{Allowed: false, Reason: "insufficient permissions"}, nil
}
