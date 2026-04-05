package application

import (
	"context"
	"fmt"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// specification is the interface for permission specifications (Specification pattern).
type specification interface {
	IsSatisfiedBy(ctx context.Context, roles []string) (bool, error)
}

// PermissionSpecification checks if any role grants the required permission.
type PermissionSpecification struct {
	roleRepo domain.RoleRepository
	resource string
	action   string
}

// Verify that PermissionSpecification satisfies the specification interface at compile time.
var _ specification = (*PermissionSpecification)(nil)

// NewPermissionSpecification creates a specification that checks resource/action permission.
func NewPermissionSpecification(roleRepo domain.RoleRepository, resource, action string) *PermissionSpecification {
	return &PermissionSpecification{roleRepo: roleRepo, resource: resource, action: action}
}

// IsSatisfiedBy returns true if any of the given roles grants the configured permission.
// A not-found error for a role is treated as "no permission" and iteration continues.
// Any other repository error is propagated so callers can distinguish infra failures
// from genuine access denials.
func (s *PermissionSpecification) IsSatisfiedBy(ctx context.Context, roles []string) (bool, error) {
	for _, roleName := range roles {
		role, err := s.roleRepo.FindByName(ctx, roleName)
		if err != nil {
			if apperrors.IsNotFound(err) {
				continue
			}
			return false, fmt.Errorf("finding role %q: %w", roleName, err)
		}
		for _, perm := range role.Permissions {
			if perm.Resource == s.resource && perm.Action == s.action {
				return true, nil
			}
		}
	}
	return false, nil
}
